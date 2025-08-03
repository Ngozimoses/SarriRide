const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sanitizeHtml = require('sanitize-html');
const winston = require('winston');
const Driver = require('../models/Driver');
const RefreshToken = require('../models/RefreshToken');
const redis = require('../Config/redis');
const { encrypt, decrypt } = require('../utils/encryptDecrypt');
const sendEmail = require('../utils/sendMail');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

const CONFIG = {
  JWT_ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY_DAYS: 7,
  OTP_EXPIRY_MS: 3600000,
  MAX_LOGIN_ATTEMPTS: 5,
  ACCOUNT_LOCK_DURATION_MS: 15 * 60 * 1000,
};

const validateEnv = () => {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is required');
  if (!process.env.ENCRYPTION_KEY) throw new Error('ENCRYPTION_KEY is required');
};

const DriverRegistration = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during driver registration', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
    }

    const { email, FirstName, LastName, password } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedFirstName = sanitizeHtml(FirstName.trim().charAt(0).toUpperCase() + FirstName.trim().slice(1).toLowerCase());
    const sanitizedLastName = sanitizeHtml(LastName.trim().charAt(0).toUpperCase() + LastName.trim().slice(1).toLowerCase());
    const sanitizedPassword = password.trim();

    const existingDriver = await Driver.findOne({ email: sanitizedEmail }).lean();
    if (existingDriver) {
      logger.warn('Email already registered', { email: sanitizedEmail });
      return res.status(400).json({ status: 'error', message: 'Email already registered' });
    }

    const newDriver = new Driver({
      email: sanitizedEmail,
      password: sanitizedPassword,
      FirstName: sanitizedFirstName,
      LastName: sanitizedLastName,
      role: 'driver',
    });

    const otp = crypto.randomInt(100000, 1000000).toString();
    newDriver.resetToken = otp;
    newDriver.resetTokenExpires = Date.now() + CONFIG.OTP_EXPIRY_MS;

    await newDriver.save();

    try {
      await sendEmail(sanitizedEmail, 'Verify your email', `Your OTP is: ${otp}`);
    } catch (emailErr) {
      logger.error('Failed to send verification email', { error: emailErr.message, email: sanitizedEmail });
      await Driver.findByIdAndDelete(newDriver._id);
      return res.status(500).json({ status: 'error', message: 'Failed to send verification email' });
    }

    logger.info('Driver registered successfully', { userId: newDriver._id, email: sanitizedEmail });
    return res.status(200).json({
      status: 'success',
      message: 'Registration successful',
      data: {
        user: {
          _id: newUser._id,
          email: newUser.email,
          role: newUser.role,
          isVerified: newUser.isVerified,
        },
      },
    });
  } catch (error) {
    logger.error('Driver registration error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const DriverLogin = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during driver login', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid credentials', data: { errors: errors.array() } });
    }

    const { email, password } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedPassword = password.trim();

    const user = await Driver.findOne({ email: sanitizedEmail, role: 'driver' }).select('+password').lean();
    if (!user) {
      logger.warn('Driver account does not exist', { email: sanitizedEmail });
      return res.status(400).json({ status: 'error', message: 'Account does not exist' });
    }

    if (user.googleId && !user.password) {
      logger.warn('Attempted password login for Google driver account', { email: sanitizedEmail });
      return res.status(403).json({ status: 'error', message: 'Please use Google Sign-In', authMethod: 'google' });
    }

    if (user.lockUntil && user.lockUntil > Date.now()) {
      logger.warn('Driver account locked', { email: sanitizedEmail });
      return res.status(403).json({ status: 'error', message: 'Account locked. Try again later.' });
    }

    const isMatch = await bcrypt.compare(sanitizedPassword, user.password);
    if (!isMatch) {
      await Driver.updateOne(
        { _id: user._id },
        { $inc: { failedLoginAttempts: 1 }, $set: { lockUntil: user.failedLoginAttempts + 1 >= CONFIG.MAX_LOGIN_ATTEMPTS ? Date.now() + CONFIG.ACCOUNT_LOCK_DURATION_MS : null } }
      );
      logger.warn('Invalid password attempt for driver', { email: sanitizedEmail, attempts: user.failedLoginAttempts + 1 });
      return res.status(400).json({ status: 'error', message: 'Invalid email or password' });
    }

    await Driver.updateOne({ _id: user._id }, { $set: { failedLoginAttempts: 0, lockUntil: null } });

    if (!user.isVerified && process.env.NODE_ENV !== 'test') {
      logger.warn('Unverified driver email login attempt', { email: sanitizedEmail });
      return res.status(403).json({ status: 'error', message: 'Email not verified' });
    }

    const accessToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
    });
    const refreshToken = crypto.randomBytes(64).toString('hex');
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const refreshTokenExpires = new Date();
    refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

    const newRefreshToken = new RefreshToken({
      userId: user._id,
      token: hashedToken,
      expiresAt: refreshTokenExpires,
      userAgent: req.headers['user-agent'] || 'unknown',
      ipAddress: req.ip || 'unknown',
    });
    await newRefreshToken.save();

    const encryptedAccessToken = encrypt(accessToken);
    const encryptedRefreshToken = encrypt(refreshToken);

    logger.info('Driver logged in successfully', { userId: user._id, email: sanitizedEmail });
    return res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: {
        user: {
          name: user.FirstName,
          _id: user._id,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
        },
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      },
    });
  } catch (error) {
    logger.error('Driver login error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const DriverRefreshToken = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during driver refresh token', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { refreshToken: encryptedRefreshToken } = req.body;
    if (!encryptedRefreshToken) {
      logger.warn('Refresh token missing for driver');
      return res.status(401).json({ status: 'error', message: 'Refresh token required' });
    }

    let refreshToken;
    try {
      refreshToken = decrypt(encryptedRefreshToken);
    } catch (error) {
      logger.warn('Invalid driver refresh token format', { error: error.message });
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const tokenDoc = await RefreshToken.findOne({
      token: hashedToken,
      revoked: false,
      expiresAt: { $gt: new Date() },
    }).lean();

    if (!tokenDoc) {
      logger.warn('Invalid or expired driver refresh token');
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    const user = await Driver.findOne({ _id: tokenDoc.userId, role: 'driver' }).lean();
    if (!user) {
      logger.warn('Driver not found for refresh token', { userId: tokenDoc.userId });
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    const newAccessToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
    });
    const newRefreshToken = crypto.randomBytes(64).toString('hex');
    const hashedNewToken = await bcrypt.hash(newRefreshToken, 10);
    const refreshTokenExpires = new Date();
    refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

    const newTokenDoc = new RefreshToken({
      userId: user._id,
      token: hashedNewToken,
      expiresAt: refreshTokenExpires,
      userAgent: req.headers['user-agent'] || 'unknown',
      ipAddress: req.ip || 'unknown',
    });

    await Promise.all([
      RefreshToken.updateOne({ _id: tokenDoc._id }, { $set: { revoked: true, revokedAt: new Date(), replacedByTokenId: newTokenDoc._id } }),
      newTokenDoc.save(),
      redis.set(`blacklist:${tokenDoc._id}`, 'revoked', 'EX', Math.floor((tokenDoc.expiresAt - Date.now()) / 1000)),
    ]);

    const encryptedNewAccessToken = encrypt(newAccessToken);
    const encryptedNewRefreshToken = encrypt(newRefreshToken);

    logger.info('Driver access token refreshed', { userId: user._id, email: user.email });
    return res.json({
      status: 'success',
      message: 'Access token refreshed',
      data: {
        user: {
          name: user.FirstName,
          _id: user._id,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
        },
        accessToken: encryptedNewAccessToken,
        refreshToken: encryptedNewRefreshToken,
      },
    });
  } catch (error) {
    logger.error('Driver refresh token error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const DriverLogout = async (req, res) => {
  try {
    const { refreshToken: encryptedRefreshToken } = req.body;
    if (!encryptedRefreshToken) {
      logger.warn('Refresh token missing for driver logout');
      return res.status(400).json({ status: 'error', message: 'Refresh token required' });
    }

    let refreshToken;
    try {
      refreshToken = decrypt(encryptedRefreshToken);
    } catch (error) {
      logger.warn('Invalid driver refresh token format for logout', { error: error.message });
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const tokenDoc = await RefreshToken.findOne({
      token: hashedToken,
      revoked: false,
      expiresAt: { $gt: new Date() },
    });

    if (!tokenDoc) {
      logger.warn('Invalid or expired driver refresh token for logout');
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    await Promise.all([
      RefreshToken.updateOne({ _id: tokenDoc._id }, { $set: { revoked: true, revokedAt: new Date() } }),
      redis.set(`blacklist:${tokenDoc._id}`, 'revoked', 'EX', Math.floor((tokenDoc.expiresAt - Date.now()) / 1000)),
    ]);

    logger.info('Driver logged out successfully', { userId: tokenDoc.userId });
    return res.status(200).json({ status: 'success', message: 'Logout successful' });
  } catch (error) {
    logger.error('Driver logout error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

validateEnv();

module.exports = {
  DriverRegistration,
  DriverLogin,
  DriverRefreshToken,
  DriverLogout,
};
