const { validationResult } = require('express-validator');
const { passport, generateStateToken } = require('../passport');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sanitizeHtml = require('sanitize-html');
const winston = require('winston');
const Client = require('../models/Client');
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
  OTP_EXPIRY_MS: 3600000, // 1 hour
  MAX_LOGIN_ATTEMPTS: 5,
  ACCOUNT_LOCK_DURATION_MS: 15 * 60 * 1000, // 15 minutes
  REDIS_KEY_PREFIX: 'auth:', // Prefix for Redis keys
  LOGIN_RATE_LIMIT: {
    WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    MAX_ATTEMPTS: 10, // Max login attempts per window
  },
  USER_CACHE_TTL: 3600, // 1 hour
};


// Validate environment variables

const validateEnv = () => {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is required');
  if (!process.env.ENCRYPTION_KEY) throw new Error('ENCRYPTION_KEY is required');
  if (!process.env.FACEBOOK_APP_SECRET) throw new Error('FACEBOOK_APP_SECRET is required');
  if (!process.env.FACEBOOK_APP_ID) throw new Error('FACEBOOK_APP_ID is required');
};

// Parse Facebook signed_request
const parseSignedRequest = (signedRequest) => {
  try {
    const [encodedSig, payload] = signedRequest.split('.');
    const secret = process.env.FACEBOOK_APP_SECRET;
    const decodedSig = Buffer.from(encodedSig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const decodedPayload = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
    const data = JSON.parse(decodedPayload);

    if (!data.algorithm || data.algorithm.toUpperCase() !== 'HMAC-SHA256') {
      throw new Error('Unknown algorithm: ' + data.algorithm);
    }

    const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (encodedSig !== expectedSig) {
      throw new Error('Invalid signature');
    }

    return data;
  } catch (error) {
    logger.error('Failed to parse signed_request', { error: error.message });
    return null;
  }
};

const ClientRegistration = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during client registration', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
    }

    const { email, FirstName, LastName, password, googleId, facebookId } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedFirstName = sanitizeHtml(FirstName.trim().charAt(0).toUpperCase() + FirstName.trim().slice(1).toLowerCase());
    const sanitizedLastName = sanitizeHtml(LastName.trim().charAt(0).toUpperCase() + LastName.trim().slice(1).toLowerCase());
    const sanitizedPassword = password ? password.trim() : undefined;
    const sanitizedGoogleId = googleId ? sanitizeHtml(googleId.trim()) : undefined;
    const sanitizedFacebookId = facebookId ? sanitizeHtml(facebookId.trim()) : undefined;

    // Rate-limiting for registration attempts
    const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}register:${sanitizedEmail}`;
    const attempts = await redis.get(rateLimitKey);
    if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
      logger.warn('Registration rate limit exceeded', { email: sanitizedEmail });
      return res.status(429).json({ status: 'error', message: 'Too many registration attempts. Try again later.' });
    }
    await redis.incr(rateLimitKey);
    await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

    const existingClient = await Client.findOne({
      $or: [
        { email: sanitizedEmail },
        ...(sanitizedGoogleId ? [{ googleId: sanitizedGoogleId }] : []),
        ...(sanitizedFacebookId ? [{ facebookId: sanitizedFacebookId }] : []),
      ],
    }).lean();
    if (existingClient) {
      logger.warn('Client already registered', { email: sanitizedEmail, googleId: sanitizedGoogleId, facebookId: sanitizedFacebookId });
      return res.status(400).json({ status: 'error', message: 'Email or third-party ID already registered' });
    }

    const newClient = new Client({
      email: sanitizedEmail,
      password: sanitizedPassword,
      googleId: sanitizedGoogleId,
      facebookId: sanitizedFacebookId,
      FirstName: sanitizedFirstName,
      LastName: sanitizedLastName,
      role: 'client',
    });

    const otp = crypto.randomInt(100000, 1000000).toString();
    newClient.resetToken = otp;
    newClient.resetTokenExpires = Date.now() + CONFIG.OTP_EXPIRY_MS;

    await newClient.save();

    // Cache OTP in Redis
    const otpKey = `${CONFIG.REDIS_KEY_PREFIX}otp:${newClient._id}`;
    try {
      await redis.set(otpKey, otp, 'EX', Math.floor(CONFIG.OTP_EXPIRY_MS / 1000));
    } catch (redisError) {
      logger.warn('Failed to cache OTP in Redis', { error: redisError.message, clientId: newClient._id });
    }

    try {
      await sendEmail(sanitizedEmail, 'Verify your email', `Your OTP is: ${otp}`);
    } catch (emailErr) {
      logger.error('Failed to send verification email', { error: emailErr.message, email: sanitizedEmail });
      await Client.findByIdAndDelete(newClient._id);
      await redis.del(otpKey);
      return res.status(500).json({ status: 'error', message: 'Failed to send verification email' });
    }

    logger.info('Client registered successfully', { clientId: newClient._id, email: sanitizedEmail });
    return res.status(200).json({
      status: 'success',
      message: 'Registration successful, OTP sent',
      data: {
        client: {
          _id: newClient._id,
          email: newClient.email,
          role: newClient.role,
          isVerified: newClient.isVerified,
        },
      },
    });
  } catch (error) {
    logger.error('Client registration error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const ClientLogin = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during client login', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid credentials', data: { errors: errors.array() } });
    }

    const { email, password, googleId, facebookId } = req.body;
    const sanitizedEmail = email ? email.trim().toLowerCase() : undefined;
    const sanitizedPassword = password ? password.trim() : undefined;
    const sanitizedGoogleId = googleId ? sanitizeHtml(googleId.trim()) : undefined;
    const sanitizedFacebookId = facebookId ? sanitizeHtml(facebookId.trim()) : undefined;

    // Rate-limiting for login attempts
    const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}login:${sanitizedEmail || sanitizedGoogleId || sanitizedFacebookId}`;
    const attempts = await redis.get(rateLimitKey);
    if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
      logger.warn('Login rate limit exceeded', { email: sanitizedEmail, googleId: sanitizedGoogleId, facebookId: sanitizedFacebookId });
      return res.status(429).json({ status: 'error', message: 'Too many login attempts. Try again later.' });
    }
    await redis.incr(rateLimitKey);
    await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

    const query = {
      $or: [
        ...(sanitizedEmail ? [{ email: sanitizedEmail, role: 'client' }] : []),
        ...(sanitizedGoogleId ? [{ googleId: sanitizedGoogleId, role: 'client' }] : []),
        ...(sanitizedFacebookId ? [{ facebookId: sanitizedFacebookId, role: 'client' }] : []),
      ],
    };

    let client;
    const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${sanitizedEmail || sanitizedGoogleId || sanitizedFacebookId}:client`;
    const cachedClient = await redis.get(cacheKey);
    if (cachedClient) {
      client = JSON.parse(cachedClient);
    } else {
      client = await Client.findOne(query).select('+password').lean();
      if (client) {
        await redis.set(cacheKey, JSON.stringify(client), 'EX', 3600); // Cache for 1 hour
      }
    }

    if (!client) {
      logger.warn('Client account does not exist', { email: sanitizedEmail, googleId: sanitizedGoogleId, facebookId: sanitizedFacebookId });
      return res.status(400).json({ status: 'error', message: 'Account does not exist' });
    }

    if (client.lockUntil && client.lockUntil > Date.now()) {
      logger.warn('Client account locked', { email: client.email });
      return res.status(403).json({ status: 'error', message: 'Account locked. Try again later.' });
    }

    if (sanitizedPassword) {
      if (!client.password) {
        logger.warn('Password login attempted for third-party client account', { email: client.email });
        return res.status(403).json({ status: 'error', message: 'Please use third-party sign-in' });
      }
      const isMatch = await bcrypt.compare(sanitizedPassword, client.password);
      if (!isMatch) {
        await Client.updateOne(
          { _id: client._id },
          { $inc: { failedLoginAttempts: 1 }, $set: { lockUntil: client.failedLoginAttempts + 1 >= CONFIG.MAX_LOGIN_ATTEMPTS ? Date.now() + CONFIG.ACCOUNT_LOCK_DURATION_MS : null } }
        );
        await redis.del(cacheKey); // Invalidate cache on update
        logger.warn('Invalid password attempt for client', { email: client.email, attempts: client.failedLoginAttempts + 1 });
        return res.status(400).json({ status: 'error', message: 'Invalid email or password' });
      }
    } else if (!client.googleId && !client.facebookId) {
      logger.warn('No password provided for non-third-party client account', { email: client.email });
      return res.status(400).json({ status: 'error', message: 'Password required for this account' });
    }else if (client.googleId && !client.facebookId) {
      logger.warn('No Facebook ID provided for non-third-party client account', { email: client.email });
      return res.status(400).json({ status: 'error', message: 'Google ID required for this account' });
    }else if (client.facebookId && !client.googleId) {
      logger.warn('No google  ID provided for non-third-party client account', { email: client.email });
      return res.status(400).json({ status: 'error', message: 'Facebook ID required for this account' });
    }

    await Client.updateOne({ _id: client._id }, { $set: { failedLoginAttempts: 0, lockUntil: null } });
    await redis.del(cacheKey); // Invalidate cache after update

    if (!client.isVerified && process.env.NODE_ENV !== 'test') {
      logger.warn('Unverified client email login attempt', { email: client.email });
      return res.status(403).json({ status: 'error', message: 'Email not verified' });
    }

    const accessToken = jwt.sign({ id: client._id, role: client.role }, process.env.JWT_SECRET, {
      expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
    });
    const refreshToken = crypto.randomBytes(64).toString('hex');
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const refreshTokenExpires = new Date();
    refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

    const newRefreshToken = new RefreshToken({
      userId: client._id,
      userModel: 'Client',
      token: hashedToken,
      expiresAt: refreshTokenExpires,
      userAgent: req.headers['user-agent'] || 'unknown',
      ipAddress: req.ip || 'unknown',
    });
    await newRefreshToken.save();

    const encryptedAccessToken = encrypt(accessToken);
    const encryptedRefreshToken = encrypt(refreshToken);

    logger.info('Client logged in successfully', { clientId: client._id, email: client.email });
    return res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: {
        client: {
          name: client.FirstName,
          _id: client._id,
          email: client.email,
          role: client.role,
          isVerified: client.isVerified,
        },
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      },
    });
  } catch (error) {
    logger.error('Client login error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const ClientRefreshToken = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during client refresh token', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { refreshToken: encryptedRefreshToken } = req.body;
    if (!encryptedRefreshToken) {
      logger.warn('Refresh token missing for client');
      return res.status(401).json({ status: 'error', message: 'Refresh token required' });
    }

    let refreshToken;
    try {
      refreshToken = decrypt(encryptedRefreshToken);
    } catch (error) {
      logger.warn('Invalid client refresh token format', { error: error.message });
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const tokenDoc = await RefreshToken.findOne({
      token: hashedToken,
      userModel: 'Client',
      revoked: false,
      expiresAt: { $gt: new Date() },
    }).lean();

    if (!tokenDoc) {
      logger.warn('Invalid or expired client refresh token');
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    const clientCacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${tokenDoc.userId}:client`;
    let client = await redis.get(clientCacheKey);
    if (client) {
      client = JSON.parse(client);
    } else {
      client = await Client.findOne({ _id: tokenDoc.userId, role: 'client' }).lean();
      if (client) {
        await redis.set(clientCacheKey, JSON.stringify(client), 'EX', 3600);
      }
    }

    if (!client) {
      logger.warn('Client not found for refresh token', { clientId: tokenDoc.userId });
      return res.status(404).json({ status: 'error', message: 'Client not found' });
    }

    const newAccessToken = jwt.sign({ id: client._id, role: client.role }, process.env.JWT_SECRET, {
      expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
    });
    const newRefreshToken = crypto.randomBytes(64).toString('hex');
    const hashedNewToken = await bcrypt.hash(newRefreshToken, 10);
    const refreshTokenExpires = new Date();
    refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

    const newTokenDoc = new RefreshToken({
      userId: client._id,
      userModel: 'Client',
      token: hashedNewToken,
      expiresAt: refreshTokenExpires,
      userAgent: req.headers['user-agent'] || 'unknown',
      ipAddress: req.ip || 'unknown',
    });

    try {
      await Promise.all([
        RefreshToken.updateOne({ _id: tokenDoc._id }, { $set: { revoked: true, revokedAt: new Date(), replacedByTokenId: newTokenDoc._id } }),
        newTokenDoc.save(),
        redis.set(`${CONFIG.REDIS_KEY_PREFIX}blacklist:${tokenDoc._id}`, 'revoked', 'EX', Math.floor((tokenDoc.expiresAt - Date.now()) / 1000)),
      ]);
    } catch (redisError) {
      logger.error('Redis error during token refresh', { error: redisError.message });
      throw redisError; // Let the outer catch handle rollback if needed
    }

    const encryptedNewAccessToken = encrypt(newAccessToken);
    const encryptedNewRefreshToken = encrypt(newRefreshToken);

    logger.info('Client access token refreshed', { clientId: client._id, email: client.email });
    return res.json({
      status: 'success',
      message: 'Access token refreshed',
      data: {
        client: {
          name: client.FirstName,
          _id: client._id,
          email: client.email,
          role: client.role,
          isVerified: client.isVerified,
        },
        accessToken: encryptedNewAccessToken,
        refreshToken: encryptedNewRefreshToken,
      },
    });
  } catch (error) {
    logger.error('Client refresh token error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const ClientLogout = async (req, res) => {
  try {
    const { refreshToken: encryptedRefreshToken } = req.body;
    if (!encryptedRefreshToken) {
      logger.warn('Refresh token missing for client logout');
      return res.status(400).json({ status: 'error', message: 'Refresh token required' });
    }

    let refreshToken;
    try {
      refreshToken = decrypt(encryptedRefreshToken);
    } catch (error) {
      logger.warn('Invalid client refresh token format for logout', { error: error.message });
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const tokenDoc = await RefreshToken.findOne({
      token: hashedToken,
      userModel: 'Client',
      revoked: false,
      expiresAt: { $gt: new Date() },
    });

    if (!tokenDoc) {
      logger.warn('Invalid or expired client refresh token for logout');
      return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
    }

    try {
      await Promise.all([
        RefreshToken.updateOne({ _id: tokenDoc._id }, { $set: { revoked: true, revokedAt: new Date() } }),
        redis.set(`${CONFIG.REDIS_KEY_PREFIX}blacklist:${tokenDoc._id}`, 'revoked', 'EX', Math.floor((tokenDoc.expiresAt - Date.now()) / 1000)),
      ]);
    } catch (redisError) {
      logger.error('Redis error during logout', { error: redisError.message });
      throw redisError;
    }

    logger.info('Client logged out successfully', { clientId: tokenDoc.userId });
    return res.status(200).json({ status: 'success', message: 'Logout successful' });
  } catch (error) {
    logger.error('Client logout error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const generateTokens = async (client, req) => {
  const accessToken = jwt.sign({ id: client._id, role: client.role }, process.env.JWT_SECRET, {
    expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
  });
  const refreshToken = crypto.randomBytes(64).toString('hex');
  const hashedToken = await bcrypt.hash(refreshToken, 10);
  const refreshTokenExpires = new Date();
  refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

  const newRefreshToken = new RefreshToken({
    userId: client._id,
    userModel: 'Client',
    token: hashedToken,
    expiresAt: refreshTokenExpires,
    userAgent: req.headers['user-agent'] || 'unknown',
    ipAddress: req.ip || 'unknown',
  });
  await newRefreshToken.save();

  return {
    accessToken: encrypt(accessToken),
    refreshToken: encrypt(refreshToken),
  };
};
const ClientGoogleAuth = (req, res, next) => {
  const state = generateStateToken({ authType: 'google', redirectUrl: req.query.redirectUrl || '' });
  passport.authenticate('google', { scope: ['profile', 'email'], state })(req, res, next);
};

const ClientGoogleCallback = async (req, res, next) => {
  passport.authenticate('google', { session: false }, async (err, client) => {
    try {
      if (err || !client) {
        logger.error('Google OAuth callback error', { error: err?.message });
        return res.status(401).json({ status: 'error', message: 'Google authentication failed' });
      }

      const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${client.email}:client`;
      await redis.set(cacheKey, JSON.stringify(client), 'EX', CONFIG.USER_CACHE_TTL);

      const { accessToken, refreshToken } = await generateTokens(client, req);

      logger.info('Google OAuth login successful', { clientId: client._id, email: client.email });
      await redis.set(`${CONFIG.REDIS_KEY_PREFIX}tokens:${client._id}`, JSON.stringify({ accessToken, refreshToken }), 'EX', CONFIG.USER_CACHE_TTL);
      // Return JSON for app backend
      return res.status(200).json({
        status: 'success',
        message: 'Google login successful',
        data: {
          client: {
            name: client.FirstName,
            _id: client._id,
            email: client.email,
            role: client.role,
            isVerified: client.isVerified,
          },
          accessToken,
          refreshToken,
        },
      });
    } catch (error) {
      logger.error('Google OAuth callback error', { error: error.message });
      return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
    }
  })(req, res, next);
};

const ClientFacebookAuth = (req, res, next) => {
  const state = generateStateToken({ authType: 'facebook', redirectUrl: req.query.redirectUrl || '' });
  passport.authenticate('facebook',
     { 
      // scope: ['email'], 
       scope: ['public_profile'],
      enableProof: true, 
      state: state })(req, res, next);
};

const ClientFacebookCallback = async (req, res, next) => {
  
 const { state } = req.query;

    if (!state) {
      return res.status(400).json({ error: 'Missing state token' });
    }

    try {
      const decoded = jwt.verify(state, process.env.JWT_SECRET);
      req.statePayload = decoded; // Optional, if you need it later
    } catch (err) {
      return res.status(400).json({ error: 'Invalid state token' });
    }

  passport.authenticate('facebook', { session: false }, async (err, client) => {
    try {
      if (err || !client) {
        logger.error('Facebook OAuth callback error', { error: err?.message });
        return res.status(401).json({ status: 'error', message: 'Facebook authentication failed' });
      }

      if (!client.isVerified) {
        const otp = crypto.randomInt(100000, 1000000).toString();
        await Client.updateOne(
          { _id: client._id },
          { resetToken: otp, resetTokenExpires: Date.now() + CONFIG.OTP_EXPIRY_MS }
        );
        const otpKey = `${CONFIG.REDIS_KEY_PREFIX}otp:${client._id}`;
        await redis.set(otpKey, otp, 'EX', Math.floor(CONFIG.OTP_EXPIRY_MS / 1000));
        try {
          await sendEmail(client.email, 'Verify your email', `Your OTP is: ${otp}`);
        } catch (emailErr) {
          logger.error('Failed to send verification email', { error: emailErr.message, email: client.email });
          await Client.findByIdAndDelete(client._id);
          await redis.del(otpKey);
          return res.status(500).json({ status: 'error', message: 'Failed to send verification email' });
        }
      }

      const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${client.email}:client`;
      await redis.set(cacheKey, JSON.stringify(client), 'EX', CONFIG.USER_CACHE_TTL);

      const { accessToken, refreshToken } = await generateTokens(client, req);

      logger.info('Facebook OAuth login successful', { clientId: client._id, email: client.email });

      // Return JSON for app backend
      return res.status(200).json({
        status: 'success',
        message: 'Facebook login successful',
        data: {
          client: {
            name: client.FirstName,
            _id: client._id,
            email: client.email,
            role: client.role,
            isVerified: client.isVerified,
          },
          accessToken,
          refreshToken,
        },
      });
    } catch (error) {
      logger.error('Facebook OAuth callback error', { error: error.message });
      return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
    }
  })(req, res, next);
};


// Data Deletion Request Callback
const ClientFacebookDataDeletion = async (req, res) => {
  try {
    const signedRequest = req.body.signed_request;
    if (!signedRequest) {
      logger.error('Missing signed_request in data deletion request');
      return res.status(400).json({ error: 'Missing signed_request' });
    }

    const data = parseSignedRequest(signedRequest);
    if (!data || !data.user_id) {
      logger.error('Invalid signed_request or missing user_id');
      return res.status(400).json({ error: 'Invalid signed_request' });
    }

    const facebookId = data.user_id;
    const client = await Client.findOne({ facebookId });
    if (!client) {
      logger.info('No client found for data deletion', { facebookId });
      return res.status(200).json({
        url: 'https://yourdomain.com/data-deletion-status',
        confirmation_code: `del_${facebookId}`,
      });
    }

    // Delete client data
    await Client.deleteOne({ facebookId });
    await RefreshToken.deleteMany({ userId: client._id, userModel: 'Client' });
    await redis.del(`${CONFIG.REDIS_KEY_PREFIX}user:${client.email}:client`);
    await redis.del(`${CONFIG.REDIS_KEY_PREFIX}otp:${client._id}`);

    logger.info('Client data deleted successfully', { facebookId, clientId: client._id });

    return res.status(200).json({
      url: 'https://yourdomain.com/data-deletion-status',
      confirmation_code: `del_${facebookId}`,
    });
  } catch (error) {
    logger.error('Data deletion request error', { error: error.message });
    return res.status(500).json({ error: 'Internal server error' });
  }
};

validateEnv();

module.exports = {
  ClientRegistration,
  ClientLogin,
  ClientRefreshToken,
  ClientLogout,
  ClientGoogleCallback,
  ClientFacebookCallback,
   ClientFacebookAuth,
   ClientGoogleAuth,
   ClientFacebookDataDeletion
};


