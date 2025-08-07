
const { check, validationResult } = require('express-validator');
const Driver = require('../models/Driver');
const winston = require('winston');
const { uploadToCloudinary } = require('.../Config/cloudinary');
const crypto = require('crypto');
const redis = require('../Config/redis');
const sendEmail = require('../utils/sendMail'); // Assuming same sendEmail as ClientRegistration
const sanitizeHtml = require('sanitize-html');
const CONFIG = {
  REDIS_KEY_PREFIX: 'sarriride:',
  OTP_EXPIRY_MS: 15 * 60 * 1000, // 15 minutes
  LOGIN_RATE_LIMIT: {
    MAX_ATTEMPTS: 5,
    WINDOW_MS: 15 * 60 * 1000 // 15 minutes
  }
};

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

const verifyEmail = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for email verification', { errors: errors.array(), email: req.body.email });
      return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
    }

    const { email } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();

    // Rate-limiting for verification attempts
    const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}verify-email:${sanitizedEmail}`;
    const attempts = await redis.get(rateLimitKey);
    if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
      logger.warn('Email verification rate limit exceeded', { email: sanitizedEmail });
      return res.status(429).json({ status: 'error', message: 'Too many verification attempts. Try again later.' });
    }
    await redis.incr(rateLimitKey);
    await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

    // Check if email is already registered
    let driver = await Driver.findOne({ email: sanitizedEmail }).lean();
    if (driver && driver.isVerified) {
      logger.warn('Email already verified', { email: sanitizedEmail });
      return res.status(400).json({ status: 'error', message: 'Email already verified' });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 1000000).toString();

    // Create or update driver with OTP
    if (!driver) {
      driver = new Driver({
        email: sanitizedEmail,
        role: 'driver',
        resetToken: otp,
        resetTokenExpires: Date.now() + CONFIG.OTP_EXPIRY_MS
      });
    } else {
      driver = await Driver.findOneAndUpdate(
        { email: sanitizedEmail },
        { resetToken: otp, resetTokenExpires: Date.now() + CONFIG.OTP_EXPIRY_MS },
        { new: true }
      );
    }
    await driver.save();

    // Cache OTP in Redis
    const otpKey = `${CONFIG.REDIS_KEY_PREFIX}otp:${driver._id}`;
    try {
      await redis.set(otpKey, otp, 'EX', Math.floor(CONFIG.OTP_EXPIRY_MS / 1000));
    } catch (redisError) {
      logger.warn('Failed to cache OTP in Redis', { error: redisError.message, driverId: driver._id });
    }

    // Send OTP email
    try {
      await sendEmail(sanitizedEmail, 'Verify Your Email - SarriRide', `Your OTP for email verification is: ${otp}`);
    } catch (emailErr) {
      logger.error('Failed to send verification email', { error: emailErr.message, email: sanitizedEmail });
      if (!driver.isVerified) {
        await Driver.findByIdAndDelete(driver._id);
        await redis.del(otpKey);
      }
      return res.status(500).json({ status: 'error', message: 'Failed to send verification email' });
    }

    logger.info('Email verification OTP sent', { driverId: driver._id, email: sanitizedEmail });
    return res.status(200).json({
      status: 'success',
      message: 'OTP sent to email for verification',
      data: { driverId: driver._id, email: sanitizedEmail }
    });
  } catch (error) {
    logger.error('Email verification error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const verifyDriverOtp = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for OTP verification', { errors: errors.array(), email: req.body.email });
      return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
    }

    const { email, otp } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();

    // Rate-limiting for OTP verification attempts
    const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}verify-otp:${sanitizedEmail}`;
    const attempts = await redis.get(rateLimitKey);
    if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
      logger.warn('OTP verification rate limit exceeded', { email: sanitizedEmail });
      return res.status(429).json({ status: 'error', message: 'Too many OTP verification attempts. Try again later.' });
    }
    await redis.incr(rateLimitKey);
    await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

    // Find driver
    const driver = await Driver.findOne({
      email: sanitizedEmail,
      resetToken: otp,
      resetTokenExpires: { $gt: Date.now() }
    });

    if (!driver) {
      logger.warn('Invalid or expired OTP', { email: sanitizedEmail });
      return res.status(400).json({ status: 'error', message: 'Invalid or expired OTP' });
    }

    // Mark email as verified
    driver.isVerified = true;
    driver.resetToken = undefined;
    driver.resetTokenExpires = undefined;
    await driver.save();

    // Clear OTP from Redis
    const otpKey = `${CONFIG.REDIS_KEY_PREFIX}otp:${driver._id}`;
    await redis.del(otpKey);

    logger.info('Email verified successfully', { driverId: driver._id, email: sanitizedEmail });
    return res.status(200).json({
      status: 'success',
      message: 'Email verified successfully. Proceed to complete registration.',
      data: { driverId: driver._id, email: sanitizedEmail }
    });
  } catch (error) {
    logger.error('OTP verification error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const registerDriver = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for driver registration', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const {
      email, FirstName, LastName, password, phoneNumber, DateOfBirth, Gender,
      licenseNumber, drivingLicense, currentAddress, permanentAddress, emergencyContactNumber,
      bankDetails, vehicleDetails
    } = req.body;

    // Check if email is verified
    const driver = await Driver.findOne({ email: email.trim().toLowerCase() });
    if (!driver || !driver.isVerified) {
      logger.warn('Email not verified for registration', { email: email.trim().toLowerCase() });
      return res.status(400).json({ status: 'error', message: 'Email must be verified before registration' });
    }

    // Handle image uploads
    let pictureUrl = driver.picture || '';
    let frontsideImageUrl = driver.drivingLicense?.frontsideImage || '';
    let backsideImageUrl = driver.drivingLicense?.backsideImage || '';

    if (req.files?.picture) {
      pictureUrl = await uploadToCloudinary(req.files.picture[0].buffer, 'profile', driver._id.toString());
    }
    if (req.files?.frontsideImage) {
      frontsideImageUrl = await uploadToCloudinary(req.files.frontsideImage[0].buffer, 'license_front', driver._id.toString());
    }
    if (req.files?.backsideImage) {
      backsideImageUrl = await uploadToCloudinary(req.files.backsideImage[0].buffer, 'license_back', driver._id.toString());
    }

    // Validate required images
    if (!frontsideImageUrl || !backsideImageUrl) {
      logger.warn('Missing required license images', { email: email.trim().toLowerCase() });
      return res.status(400).json({ status: 'error', message: 'Frontside and backside license images are required' });
    }

    // Check for duplicates
    const existingDriver = await Driver.findOne({
      $and: [
        { _id: { $ne: driver._id } },
        {
          $or: [
            { phoneNumber },
            { licenseNumber },
            { 'vehicleDetails.licensePlate': vehicleDetails.licensePlate },
            { 'bankDetails.bankAccountNumber': bankDetails.bankAccountNumber }
          ]
        }
      ]
    });
    if (existingDriver) {
      logger.warn('Duplicate driver data', { email, phoneNumber, licenseNumber });
      return res.status(400).json({ status: 'error', message: 'Phone number, license number, license plate, or bank account number already registered' });
    }

    // Update driver with full registration details
    driver.FirstName = sanitizeHtml(FirstName.trim().charAt(0).toUpperCase() + FirstName.trim().slice(1).toLowerCase());
    driver.LastName = sanitizeHtml(LastName.trim().charAt(0).toUpperCase() + LastName.trim().slice(1).toLowerCase());
    driver.password = password.trim();
    driver.phoneNumber = phoneNumber;
    driver.DateOfBirth = DateOfBirth;
    driver.Gender = Gender;
    driver.licenseNumber = licenseNumber;
    driver.drivingLicense = {
      issueDate: drivingLicense.issueDate,
      expiryDate: drivingLicense.expiryDate,
      frontsideImage: frontsideImageUrl,
      backsideImage: backsideImageUrl
    };
    driver.currentAddress = currentAddress;
    driver.permanentAddress = permanentAddress;
    driver.emergencyContactNumber = emergencyContactNumber;
    driver.bankDetails = bankDetails;
    driver.vehicleDetails = vehicleDetails;

    await driver.save();

    logger.info('Driver registered successfully', { driverId: driver._id, email: email.trim().toLowerCase() });
    return res.status(201).json({
      status: 'success',
      message: 'Driver registered successfully. Awaiting admin verification.',
      data: { driverId: driver._id, email: driver.email }
    });
  } catch (error) {
    logger.error('Driver registration error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const uploadImages = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for image upload', { errors: errors.array(), driverId: req.user?._id });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const driverId = req.user._id;
    const { picture, frontsideImage, backsideImage } = req.files;

    const updates = {};

    if (picture) {
      updates.picture = await uploadToCloudinary(picture[0].buffer, 'profile', driverId);
    }
    if (frontsideImage) {
      updates['drivingLicense.frontsideImage'] = await uploadToCloudinary(frontsideImage[0].buffer, 'license_front', driverId);
    }
    if (backsideImage) {
      updates['drivingLicense.backsideImage'] = await uploadToCloudinary(backsideImage[0].buffer, 'license_back', driverId);
    }

    if (Object.keys(updates).length === 0) {
      logger.warn('No images provided for upload', { driverId });
      return res.status(400).json({ status: 'error', message: 'At least one image is required' });
    }

    const driver = await Driver.findByIdAndUpdate(
      driverId,
      { $set: updates },
      { new: true, select: '_id picture drivingLicense.frontsideImage drivingLicense.backsideImage' }
    );

    if (!driver) {
      logger.warn('Driver not found for image upload', { driverId });
      return res.status(404).json({ status: 'error', message: 'Driver not found' });
    }

    logger.info('Images uploaded successfully', { driverId, updates });
    return res.status(200).json({
      status: 'success',
      message: 'Images uploaded successfully',
      data: {
        driverId: driver._id,
        picture: driver.picture,
        frontsideImage: driver.drivingLicense.frontsideImage,
        backsideImage: driver.drivingLicense.backsideImage
      }
    });
  } catch (error) {
    logger.error('Image upload error', { driverId: req.user?._id, error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

module.exports = { verifyEmail, verifyDriverOtp, registerDriver, uploadImages };























// const { validationResult } = require('express-validator');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const crypto = require('crypto');
// const sanitizeHtml = require('sanitize-html');
// const winston = require('winston');
// const Driver = require('../models/Driver');
// const RefreshToken = require('../models/RefreshToken');
// const redis = require('../Config/redis');
// const { encrypt, decrypt } = require('../utils/encryptDecrypt');
// const sendEmail = require('../utils/sendMail');

// const logger = winston.createLogger({
//   level: 'info',
//   format: winston.format.combine(
//     winston.format.timestamp(),
//     winston.format.json()
//   ),
//   transports: [
//     new winston.transports.Console(),
//     new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
//     new winston.transports.File({ filename: 'logs/combined.log' })
//   ]
// });

// const CONFIG = {
//   JWT_ACCESS_TOKEN_EXPIRY: '15m',
//   REFRESH_TOKEN_EXPIRY_DAYS: 7,
//   OTP_EXPIRY_MS: 3600000,
//   MAX_LOGIN_ATTEMPTS: 5,
//   ACCOUNT_LOCK_DURATION_MS: 15 * 60 * 1000,
// };

// const validateEnv = () => {
//   if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is required');
//   if (!process.env.ENCRYPTION_KEY) throw new Error('ENCRYPTION_KEY is required');
// };

// const DriverRegistration = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed during driver registration', { errors: errors.array() });
//       return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
//     }

//     const { email, FirstName, LastName, password } = req.body;
//     const sanitizedEmail = email.trim().toLowerCase();
//     const sanitizedFirstName = sanitizeHtml(FirstName.trim().charAt(0).toUpperCase() + FirstName.trim().slice(1).toLowerCase());
//     const sanitizedLastName = sanitizeHtml(LastName.trim().charAt(0).toUpperCase() + LastName.trim().slice(1).toLowerCase());
//     const sanitizedPassword = password.trim();

//     const existingDriver = await Driver.findOne({ email: sanitizedEmail }).lean();
//     if (existingDriver) {
//       logger.warn('Email already registered', { email: sanitizedEmail });
//       return res.status(400).json({ status: 'error', message: 'Email already registered' });
//     }

//     const newDriver = new Driver({
//       email: sanitizedEmail,
//       password: sanitizedPassword,
//       FirstName: sanitizedFirstName,
//       LastName: sanitizedLastName,
//       role: 'driver',
//     });

//     const otp = crypto.randomInt(100000, 1000000).toString();
//     newDriver.resetToken = otp;
//     newDriver.resetTokenExpires = Date.now() + CONFIG.OTP_EXPIRY_MS;

//     await newDriver.save();

//     try {
//       await sendEmail(sanitizedEmail, 'Verify your email', `Your OTP is: ${otp}`);
//     } catch (emailErr) {
//       logger.error('Failed to send verification email', { error: emailErr.message, email: sanitizedEmail });
//       await Driver.findByIdAndDelete(newDriver._id);
//       return res.status(500).json({ status: 'error', message: 'Failed to send verification email' });
//     }

//     logger.info('Driver registered successfully', { userId: newDriver._id, email: sanitizedEmail });
//     return res.status(200).json({
//       status: 'success',
//       message: 'Registration successful',
//       data: {
//         user: {
//           _id: newUser._id,
//           email: newUser.email,
//           role: newUser.role,
//           isVerified: newUser.isVerified,
//         },
//       },
//     });
//   } catch (error) {
//     logger.error('Driver registration error', { error: error.message, email: req.body.email });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// const DriverLogin = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed during driver login', { errors: errors.array() });
//       return res.status(400).json({ status: 'error', message: 'Invalid credentials', data: { errors: errors.array() } });
//     }

//     const { email, password } = req.body;
//     const sanitizedEmail = email.trim().toLowerCase();
//     const sanitizedPassword = password.trim();

//     const user = await Driver.findOne({ email: sanitizedEmail, role: 'driver' }).select('+password').lean();
//     if (!user) {
//       logger.warn('Driver account does not exist', { email: sanitizedEmail });
//       return res.status(400).json({ status: 'error', message: 'Account does not exist' });
//     }

//     if (user.googleId && !user.password) {
//       logger.warn('Attempted password login for Google driver account', { email: sanitizedEmail });
//       return res.status(403).json({ status: 'error', message: 'Please use Google Sign-In', authMethod: 'google' });
//     }

//     if (user.lockUntil && user.lockUntil > Date.now()) {
//       logger.warn('Driver account locked', { email: sanitizedEmail });
//       return res.status(403).json({ status: 'error', message: 'Account locked. Try again later.' });
//     }

//     const isMatch = await bcrypt.compare(sanitizedPassword, user.password);
//     if (!isMatch) {
//       await Driver.updateOne(
//         { _id: user._id },
//         { $inc: { failedLoginAttempts: 1 }, $set: { lockUntil: user.failedLoginAttempts + 1 >= CONFIG.MAX_LOGIN_ATTEMPTS ? Date.now() + CONFIG.ACCOUNT_LOCK_DURATION_MS : null } }
//       );
//       logger.warn('Invalid password attempt for driver', { email: sanitizedEmail, attempts: user.failedLoginAttempts + 1 });
//       return res.status(400).json({ status: 'error', message: 'Invalid email or password' });
//     }

//     await Driver.updateOne({ _id: user._id }, { $set: { failedLoginAttempts: 0, lockUntil: null } });

//     if (!user.isVerified && process.env.NODE_ENV !== 'test') {
//       logger.warn('Unverified driver email login attempt', { email: sanitizedEmail });
//       return res.status(403).json({ status: 'error', message: 'Email not verified' });
//     }

//     const accessToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
//       expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
//     });
//     const refreshToken = crypto.randomBytes(64).toString('hex');
//     const hashedToken = await bcrypt.hash(refreshToken, 10);
//     const refreshTokenExpires = new Date();
//     refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

//     const newRefreshToken = new RefreshToken({
//       userId: user._id,
//       token: hashedToken,
//       expiresAt: refreshTokenExpires,
//       userAgent: req.headers['user-agent'] || 'unknown',
//       ipAddress: req.ip || 'unknown',
//     });
//     await newRefreshToken.save();

//     const encryptedAccessToken = encrypt(accessToken);
//     const encryptedRefreshToken = encrypt(refreshToken);

//     logger.info('Driver logged in successfully', { userId: user._id, email: sanitizedEmail });
//     return res.status(200).json({
//       status: 'success',
//       message: 'Login successful',
//       data: {
//         user: {
//           name: user.FirstName,
//           _id: user._id,
//           email: user.email,
//           role: user.role,
//           isVerified: user.isVerified,
//         },
//         accessToken: encryptedAccessToken,
//         refreshToken: encryptedRefreshToken,
//       },
//     });
//   } catch (error) {
//     logger.error('Driver login error', { error: error.message, email: req.body.email });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// const DriverRefreshToken = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed during driver refresh token', { errors: errors.array() });
//       return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
//     }

//     const { refreshToken: encryptedRefreshToken } = req.body;
//     if (!encryptedRefreshToken) {
//       logger.warn('Refresh token missing for driver');
//       return res.status(401).json({ status: 'error', message: 'Refresh token required' });
//     }

//     let refreshToken;
//     try {
//       refreshToken = decrypt(encryptedRefreshToken);
//     } catch (error) {
//       logger.warn('Invalid driver refresh token format', { error: error.message });
//       return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
//     }

//     const hashedToken = await bcrypt.hash(refreshToken, 10);
//     const tokenDoc = await RefreshToken.findOne({
//       token: hashedToken,
//       revoked: false,
//       expiresAt: { $gt: new Date() },
//     }).lean();

//     if (!tokenDoc) {
//       logger.warn('Invalid or expired driver refresh token');
//       return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
//     }

//     const user = await Driver.findOne({ _id: tokenDoc.userId, role: 'driver' }).lean();
//     if (!user) {
//       logger.warn('Driver not found for refresh token', { userId: tokenDoc.userId });
//       return res.status(404).json({ status: 'error', message: 'User not found' });
//     }

//     const newAccessToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
//       expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
//     });
//     const newRefreshToken = crypto.randomBytes(64).toString('hex');
//     const hashedNewToken = await bcrypt.hash(newRefreshToken, 10);
//     const refreshTokenExpires = new Date();
//     refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

//     const newTokenDoc = new RefreshToken({
//       userId: user._id,
//       token: hashedNewToken,
//       expiresAt: refreshTokenExpires,
//       userAgent: req.headers['user-agent'] || 'unknown',
//       ipAddress: req.ip || 'unknown',
//     });

//     await Promise.all([
//       RefreshToken.updateOne({ _id: tokenDoc._id }, { $set: { revoked: true, revokedAt: new Date(), replacedByTokenId: newTokenDoc._id } }),
//       newTokenDoc.save(),
//       redis.set(`blacklist:${tokenDoc._id}`, 'revoked', 'EX', Math.floor((tokenDoc.expiresAt - Date.now()) / 1000)),
//     ]);

//     const encryptedNewAccessToken = encrypt(newAccessToken);
//     const encryptedNewRefreshToken = encrypt(newRefreshToken);

//     logger.info('Driver access token refreshed', { userId: user._id, email: user.email });
//     return res.json({
//       status: 'success',
//       message: 'Access token refreshed',
//       data: {
//         user: {
//           name: user.FirstName,
//           _id: user._id,
//           email: user.email,
//           role: user.role,
//           isVerified: user.isVerified,
//         },
//         accessToken: encryptedNewAccessToken,
//         refreshToken: encryptedNewRefreshToken,
//       },
//     });
//   } catch (error) {
//     logger.error('Driver refresh token error', { error: error.message });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// const DriverLogout = async (req, res) => {
//   try {
//     const { refreshToken: encryptedRefreshToken } = req.body;
//     if (!encryptedRefreshToken) {
//       logger.warn('Refresh token missing for driver logout');
//       return res.status(400).json({ status: 'error', message: 'Refresh token required' });
//     }

//     let refreshToken;
//     try {
//       refreshToken = decrypt(encryptedRefreshToken);
//     } catch (error) {
//       logger.warn('Invalid driver refresh token format for logout', { error: error.message });
//       return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
//     }

//     const hashedToken = await bcrypt.hash(refreshToken, 10);
//     const tokenDoc = await RefreshToken.findOne({
//       token: hashedToken,
//       revoked: false,
//       expiresAt: { $gt: new Date() },
//     });

//     if (!tokenDoc) {
//       logger.warn('Invalid or expired driver refresh token for logout');
//       return res.status(403).json({ status: 'error', message: 'Invalid refresh token' });
//     }

//     await Promise.all([
//       RefreshToken.updateOne({ _id: tokenDoc._id }, { $set: { revoked: true, revokedAt: new Date() } }),
//       redis.set(`blacklist:${tokenDoc._id}`, 'revoked', 'EX', Math.floor((tokenDoc.expiresAt - Date.now()) / 1000)),
//     ]);

//     logger.info('Driver logged out successfully', { userId: tokenDoc.userId });
//     return res.status(200).json({ status: 'success', message: 'Logout successful' });
//   } catch (error) {
//     logger.error('Driver logout error', { error: error.message });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// validateEnv();

// module.exports = {
//   DriverRegistration,
//   DriverLogin,
//   DriverRefreshToken,
//   DriverLogout,
// };
