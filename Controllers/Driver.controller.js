const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Driver = require('../models/Driver');
const Client = require('../models/Client');
const sanitizeHtml = require('sanitize-html');
const winston = require('winston');
const { uploadToCloudinary } = require('../Config/cloudinary');
const redis = require('../Config/redis');
const sendEmail = require('../utils/sendMail');
const RefreshToken = require('../models/RefreshToken');
const { encrypt, decrypt } = require('../utils/encryptDecrypt');

const CONFIG = {
  REDIS_KEY_PREFIX: 'sarriride:',
  JWT_ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY_DAYS: 7,
  ACCOUNT_LOCK_DURATION_MS: 15 * 60 * 1000, // 15 minutes
   MAX_LOGIN_ATTEMPTS: 10,
  OTP_EXPIRY_MS: 15 * 60 * 1000, // 15 minutes
  LOGIN_RATE_LIMIT: {
    MAX_ATTEMPTS: 5,
    WINDOW_MS: 15 * 60 * 1000 // 15 minutes
  },
    USER_CACHE_TTL: 3600, // 1 hour
};

// const CONFIG = {
//   JWT_ACCESS_TOKEN_EXPIRY: '15m',
//   REFRESH_TOKEN_EXPIRY_DAYS: 7,
//   OTP_EXPIRY_MS: 3600000, // 1 hour
//   MAX_LOGIN_ATTEMPTS: 5,
//   ACCOUNT_LOCK_DURATION_MS: 15 * 60 * 1000, // 15 minutes
//   REDIS_KEY_PREFIX: 'auth:', // Prefix for Redis keys
//   LOGIN_RATE_LIMIT: {
//     WINDOW_MS: 15 * 60 * 1000, // 15 minutes
//     MAX_ATTEMPTS: 15, // Max login attempts per window
//   },
//   USER_CACHE_TTL: 3600, // 1 hour
// };

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




const DriverLogin = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during client login', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid credentials', data: { errors: errors.array() } });
    }

    const { email, password, } = req.body;
    const sanitizedEmail = email ? email.trim().toLowerCase() : undefined;
    const sanitizedPassword = password ? password.trim() : undefined;

    // Rate-limiting for login attempts
    const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}login:${sanitizedEmail }`;
    const attempts = await redis.get(rateLimitKey);
    if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
      logger.warn('Login rate limit exceeded', { email: sanitizedEmail});
      return res.status(429).json({ status: 'error', message: 'Too many login attempts. Try again later.' });
    }
    await redis.incr(rateLimitKey);
    await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

    const query = {
      $or: [
        ...(sanitizedEmail ? [{ email: sanitizedEmail, role: 'driver' }] : []),
      ],
    };

    let driver;
    const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${sanitizedEmail}:driver`;
    const cachedDriver = await redis.get(cacheKey);
    if (cachedDriver) {
      driver = JSON.parse(cachedDriver);
    } else {
      driver = await Driver.findOne(query).select('+password').lean();
      if (driver) {
        await redis.set(cacheKey, JSON.stringify(driver), 'EX', 3600); // Cache for 1 hour
      }
    }

    if (!driver) {
      logger.warn('Driver account does not exist', { email: sanitizedEmail });
      return res.status(400).json({ status: 'error', message: 'Account does not exist' });
    }

    if (driver.lockUntil && driver.lockUntil > Date.now()) {
      logger.warn('Driver account locked', { email: driver.email });
      return res.status(403).json({ status: 'error', message: 'Account locked. Try again later.' });
    }

    if (sanitizedPassword) {
      if (!driver.password) {
        logger.warn('Password login attempted for third-party driver account', { email: driver.email });
        return res.status(403).json({ status: 'error', message: 'Please use third-party sign-in' });
      }
      const isMatch = await bcrypt.compare(sanitizedPassword, driver.password);
      if (!isMatch) {
        await Driver.updateOne(
          { _id: driver._id },
          { $inc: { failedLoginAttempts: 1 }, $set: { lockUntil: driver.failedLoginAttempts + 1 >= CONFIG.MAX_LOGIN_ATTEMPTS ? Date.now() + CONFIG.ACCOUNT_LOCK_DURATION_MS : null } }
        );
        await redis.del(cacheKey); // Invalidate cache on update
        logger.warn('Invalid password attempt for driver', { email: driver.email, attempts: driver.failedLoginAttempts + 1 });
        return res.status(400).json({ status: 'error', message: 'Invalid email or password' });
      }
    }
    await Driver.updateOne({ _id: driver._id }, { $set: { failedLoginAttempts: 0, lockUntil: null } });
    await redis.del(cacheKey); // Invalidate cache after update

    if (!driver.isVerified && process.env.NODE_ENV !== 'test') {
      logger.warn('Unverified driver email login attempt', { email: driver.email });
      return res.status(403).json({ status: 'error', message: 'Email not verified' });
    }

    const accessToken = jwt.sign({ id: driver._id, role: driver.role }, process.env.JWT_SECRET, {
      expiresIn: CONFIG.JWT_ACCESS_TOKEN_EXPIRY,
    });
    const refreshToken = crypto.randomBytes(64).toString('hex');
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    const refreshTokenExpires = new Date();
    refreshTokenExpires.setDate(refreshTokenExpires.getDate() + CONFIG.REFRESH_TOKEN_EXPIRY_DAYS);

    const newRefreshToken = new RefreshToken({
      userId: driver._id,
      userModel: 'Driver',
      token: hashedToken,
      expiresAt: refreshTokenExpires,
      userAgent: req.headers['user-agent'] || 'unknown',
      ipAddress: req.ip || 'unknown',
    });
    await newRefreshToken.save();

    const encryptedAccessToken = encrypt(accessToken);
    const encryptedRefreshToken = encrypt(refreshToken);

    logger.info('Client logged in successfully', { clientId: driver._id, email: client.email });
    return res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: {
        driver: {
          name: driver.FirstName,
          _id: driver._id,
          email: driver.email,
          role: driver.role,
          isVerified: driver.isVerified,
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

const verifyEmail = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for email verification', { errors: errors.array(), email: req.body.email });
      return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
    }

    const { email } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();

    // Check if email is registered in Client collection
    const existingClient = await Client.findOne({ email: sanitizedEmail }).lean();
    if (existingClient) {
      logger.warn('Email already registered as a client', { email: sanitizedEmail, clientId: existingClient._id });
      return res.status(400).json({ status: 'error', message: 'Email already registered as a client' });
    } else {
      logger.info('No client found with email', { email: sanitizedEmail });
    }

    // Rate-limiting for verification attempts
    const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}verify-email:${sanitizedEmail}`;
    const attempts = await redis.get(rateLimitKey);
    if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
      logger.warn('Email verification rate limit exceeded', { email: sanitizedEmail });
      return res.status(429).json({ status: 'error', message: 'Too many verification attempts. Try again later.' });
    }
    await redis.incr(rateLimitKey);
    await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

    // Check if email is already registered in Driver collection
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

    // Check if email is verified in Driver collection
    const driver = await Driver.findOne({ email: email.trim().toLowerCase() });
    if (!driver || !driver.isVerified) {
      logger.warn('Email not verified for registration', { email: email.trim().toLowerCase() });
      return res.status(400).json({ status: 'error', message: 'Email must be verified before registration' });
    }

    // Check if email is registered in Client collection
    const existingClient = await Client.findOne({ email: email.trim().toLowerCase() }).lean();
    if (existingClient) {
      logger.warn('Email already registered as a client', { email: email.trim().toLowerCase() });
      return res.status(400).json({ status: 'error', message: 'Email already registered as a client' });
    }

    // Manually validate required fields
    const requiredFields = {
      FirstName: 'First name is required',
      LastName: 'Last name is required',
      password: 'Password is required',
      phoneNumber: 'Phone number is required',
      DateOfBirth: 'Date of birth is required',
      Gender: 'Gender is required',
      licenseNumber: 'License number is required',
      'drivingLicense.issueDate': 'License issue date is required',
      'drivingLicense.expiryDate': 'License expiry date is required',
      'currentAddress.address': 'Current address is required',
      'currentAddress.state': 'Current state is required',
      'currentAddress.city': 'Current city is required',
      'currentAddress.country': 'Current country is required',
      'currentAddress.postalCode': 'Current postal code is required',
      'permanentAddress.address': 'Permanent address is required',
      'permanentAddress.state': 'Permanent state is required',
      'permanentAddress.city': 'Permanent city is required',
      'permanentAddress.country': 'Permanent country is required',
      'permanentAddress.postalCode': 'Permanent postal code is required',
      emergencyContactNumber: 'Emergency contact number is required',
      'bankDetails.bankAccountNumber': 'Bank account number is required',
      'bankDetails.bankName': 'Bank name is required',
      'bankDetails.bankAccountName': 'Bank account name is required',
      'vehicleDetails.make': 'Vehicle make is required',
      'vehicleDetails.model': 'Vehicle model is required',
      'vehicleDetails.year': 'Vehicle year is required',
      'vehicleDetails.licensePlate': 'Vehicle license plate is required'
    };

    const missingFields = Object.keys(requiredFields).filter(field => {
      const value = field.includes('.') ? field.split('.').reduce((obj, key) => obj?.[key], req.body) : req.body[field];
      return !value;
    });

    if (missingFields.length > 0) {
      logger.warn('Missing required fields for registration', { email, missingFields });
      return res.status(400).json({
        status: 'error',
        message: 'Missing required fields',
        data: { errors: missingFields.map(field => ({ field, msg: requiredFields[field] })) }
      });
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
    // if (!frontsideImageUrl || !backsideImageUrl) {
    //   logger.warn('Missing required license images', { email: email.trim().toLowerCase() });
    //   return res.status(400).json({ status: 'error', message: 'Frontside and backside license images are required' });
    // }

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
// const uploadImages = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed for image upload', { errors: errors.array(), driverId: req.user?._id });
//       return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
//     }

//     const { picture, frontsideImage, backsideImage } = req.files || {};

//     // If uploading profile picture, user must be authenticated
//     if (picture && (!req.user || !req.user._id)) {
//       logger.warn('Unauthorized: Missing user info for profile picture upload');
//       return res.status(401).json({ status: 'error', message: 'Unauthorized - user ID required for profile picture upload' });
//     }

//     const driverId = req.user?._id;

//     const updates = {};

//     if (picture) {
//       updates.picture = await uploadToCloudinary(picture[0].buffer, 'profile', driverId);
//     }
//     if (frontsideImage) {
//       updates['drivingLicense.frontsideImage'] = await uploadToCloudinary(frontsideImage[0].buffer, 'license_front', driverId);
//     }
//     if (backsideImage) {
//       updates['drivingLicense.backsideImage'] = await uploadToCloudinary(backsideImage[0].buffer, 'license_back', driverId);
//     }

//     if (Object.keys(updates).length === 0) {
//       logger.warn('No images provided for upload', { driverId });
//       return res.status(400).json({ status: 'error', message: 'At least one image is required' });
//     }

//     // If driverId exists, update the driver's DB record
//     if (driverId) {
//       const driver = await Driver.findByIdAndUpdate(
//         driverId,
//         { $set: updates },
//         { new: true, select: '_id picture drivingLicense.frontsideImage drivingLicense.backsideImage' }
//       );

//       if (!driver) {
//         logger.warn('Driver not found for image upload', { driverId });
//         return res.status(404).json({ status: 'error', message: 'Driver not found' });
//       }

//       logger.info('Images uploaded successfully', { driverId, updates });
//       return res.status(200).json({
//         status: 'success',
//         message: 'Images uploaded successfully',
//         data: {
//           driverId: driver._id,
//           picture: driver.picture,
//           frontsideImage: driver.drivingLicense.frontsideImage,
//           backsideImage: driver.drivingLicense.backsideImage,
//         },
//       });
//     }

//     // No driverId, so just return the uploaded image URLs
//     logger.info('Images uploaded successfully without driver ID', { updates });
//     return res.status(200).json({
//       status: 'success',
//       message: 'Images uploaded successfully',
//       data: updates,
//     });

//   } catch (error) {
//     logger.error('Image upload error', { driverId: req.user?._id, error: error.message });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

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

module.exports = { verifyEmail, verifyDriverOtp, registerDriver, uploadImages, DriverLogin };
// const { check, validationResult } = require('express-validator');
// const Driver = require('../models/Driver');
// const winston = require('winston');
// const { uploadToCloudinary } = require('../Config/cloudinary');
// const crypto = require('crypto');
// const redis = require('../Config/redis');
// const sendEmail = require('../utils/sendMail'); // Assuming same sendEmail as ClientRegistration
// const sanitizeHtml = require('sanitize-html');
// const CONFIG = {
//   REDIS_KEY_PREFIX: 'sarriride:',
//   OTP_EXPIRY_MS: 15 * 60 * 1000, // 15 minutes
//   LOGIN_RATE_LIMIT: {
//     MAX_ATTEMPTS: 5,
//     WINDOW_MS: 15 * 60 * 1000 // 15 minutes
//   }
// };

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

// const verifyEmail = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed for email verification', { errors: errors.array(), email: req.body.email });
//       return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
//     }

//     const { email } = req.body;
//     const sanitizedEmail = email.trim().toLowerCase();

//     // Rate-limiting for verification attempts
//     const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}verify-email:${sanitizedEmail}`;
//     const attempts = await redis.get(rateLimitKey);
//     if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
//       logger.warn('Email verification rate limit exceeded', { email: sanitizedEmail });
//       return res.status(429).json({ status: 'error', message: 'Too many verification attempts. Try again later.' });
//     }
//     await redis.incr(rateLimitKey);
//     await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

//     // Check if email is already registered
//     let driver = await Driver.findOne({ email: sanitizedEmail }).lean();
//     if (driver && driver.isVerified) {
//       logger.warn('Email already verified', { email: sanitizedEmail });
//       return res.status(400).json({ status: 'error', message: 'Email already verified' });
//     }

//     // Generate OTP
//     const otp = crypto.randomInt(100000, 1000000).toString();

//     // Create or update driver with OTP
//     if (!driver) {
//       driver = new Driver({
//         email: sanitizedEmail,
//         role: 'driver',
//         resetToken: otp,
//         resetTokenExpires: Date.now() + CONFIG.OTP_EXPIRY_MS
//       });
//     } else {
//       driver = await Driver.findOneAndUpdate(
//         { email: sanitizedEmail },
//         { resetToken: otp, resetTokenExpires: Date.now() + CONFIG.OTP_EXPIRY_MS },
//         { new: true }
//       );
//     }
//     await driver.save();

//     // Cache OTP in Redis
//     const otpKey = `${CONFIG.REDIS_KEY_PREFIX}otp:${driver._id}`;
//     try {
//       await redis.set(otpKey, otp, 'EX', Math.floor(CONFIG.OTP_EXPIRY_MS / 1000));
//     } catch (redisError) {
//       logger.warn('Failed to cache OTP in Redis', { error: redisError.message, driverId: driver._id });
//     }

//     // Send OTP email
//     try {
//       await sendEmail(sanitizedEmail, 'Verify Your Email - SarriRide', `Your OTP for email verification is: ${otp}`);
//     } catch (emailErr) {
//       logger.error('Failed to send verification email', { error: emailErr.message, email: sanitizedEmail });
//       if (!driver.isVerified) {
//         await Driver.findByIdAndDelete(driver._id);
//         await redis.del(otpKey);
//       }
//       return res.status(500).json({ status: 'error', message: 'Failed to send verification email' });
//     }

//     logger.info('Email verification OTP sent', { driverId: driver._id, email: sanitizedEmail });
//     return res.status(200).json({
//       status: 'success',
//       message: 'OTP sent to email for verification',
//       data: { driverId: driver._id, email: sanitizedEmail }
//     });
//   } catch (error) {
//     logger.error('Email verification error', { error: error.message, email: req.body.email });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// const verifyDriverOtp = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed for OTP verification', { errors: errors.array(), email: req.body.email });
//       return res.status(400).json({ status: 'error', message: 'Validation failed', data: { errors: errors.array() } });
//     }

//     const { email, otp } = req.body;
//     const sanitizedEmail = email.trim().toLowerCase();

//     // Rate-limiting for OTP verification attempts
//     const rateLimitKey = `${CONFIG.REDIS_KEY_PREFIX}verify-otp:${sanitizedEmail}`;
//     const attempts = await redis.get(rateLimitKey);
//     if (attempts && parseInt(attempts) >= CONFIG.LOGIN_RATE_LIMIT.MAX_ATTEMPTS) {
//       logger.warn('OTP verification rate limit exceeded', { email: sanitizedEmail });
//       return res.status(429).json({ status: 'error', message: 'Too many OTP verification attempts. Try again later.' });
//     }
//     await redis.incr(rateLimitKey);
//     await redis.expire(rateLimitKey, CONFIG.LOGIN_RATE_LIMIT.WINDOW_MS / 1000);

//     // Find driver
//     const driver = await Driver.findOne({
//       email: sanitizedEmail,
//       resetToken: otp,
//       resetTokenExpires: { $gt: Date.now() }
//     });

//     if (!driver) {
//       logger.warn('Invalid or expired OTP', { email: sanitizedEmail });
//       return res.status(400).json({ status: 'error', message: 'Invalid or expired OTP' });
//     }

//     // Mark email as verified
//     driver.isVerified = true;
//     driver.resetToken = undefined;
//     driver.resetTokenExpires = undefined;
//     await driver.save();

//     // Clear OTP from Redis
//     const otpKey = `${CONFIG.REDIS_KEY_PREFIX}otp:${driver._id}`;
//     await redis.del(otpKey);

//     logger.info('Email verified successfully', { driverId: driver._id, email: sanitizedEmail });
//     return res.status(200).json({
//       status: 'success',
//       message: 'Email verified successfully. Proceed to complete registration.',
//       data: { driverId: driver._id, email: sanitizedEmail }
//     });
//   } catch (error) {
//     logger.error('OTP verification error', { error: error.message, email: req.body.email });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// const registerDriver = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed for driver registration', { errors: errors.array() });
//       return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
//     }

//     const {
//       email, FirstName, LastName, password, phoneNumber, DateOfBirth, Gender,
//       licenseNumber, drivingLicense, currentAddress, permanentAddress, emergencyContactNumber,
//       bankDetails, vehicleDetails
//     } = req.body;

//     // Check if email is verified
//     const driver = await Driver.findOne({ email: email.trim().toLowerCase() });
//     if (!driver || !driver.isVerified) {
//       logger.warn('Email not verified for registration', { email: email.trim().toLowerCase() });
//       return res.status(400).json({ status: 'error', message: 'Email must be verified before registration' });
//     }

//     // Handle image uploads
//     let pictureUrl = driver.picture || '';
//     let frontsideImageUrl = driver.drivingLicense?.frontsideImage || '';
//     let backsideImageUrl = driver.drivingLicense?.backsideImage || '';

//     if (req.files?.picture) {
//       pictureUrl = await uploadToCloudinary(req.files.picture[0].buffer, 'profile', driver._id.toString());
//     }
//     if (req.files?.frontsideImage) {
//       frontsideImageUrl = await uploadToCloudinary(req.files.frontsideImage[0].buffer, 'license_front', driver._id.toString());
//     }
//     if (req.files?.backsideImage) {
//       backsideImageUrl = await uploadToCloudinary(req.files.backsideImage[0].buffer, 'license_back', driver._id.toString());
//     }

//     // Validate required images
//     if (!frontsideImageUrl || !backsideImageUrl) {
//       logger.warn('Missing required license images', { email: email.trim().toLowerCase() });
//       return res.status(400).json({ status: 'error', message: 'Frontside and backside license images are required' });
//     }

//     // Check for duplicates
//     const existingDriver = await Driver.findOne({
//       $and: [
//         { _id: { $ne: driver._id } },
//         {
//           $or: [
//             { phoneNumber },
//             { licenseNumber },
//             { 'vehicleDetails.licensePlate': vehicleDetails.licensePlate },
//             { 'bankDetails.bankAccountNumber': bankDetails.bankAccountNumber }
//           ]
//         }
//       ]
//     });
//     if (existingDriver) {
//       logger.warn('Duplicate driver data', { email, phoneNumber, licenseNumber });
//       return res.status(400).json({ status: 'error', message: 'Phone number, license number, license plate, or bank account number already registered' });
//     }

//     // Update driver with full registration details
//     driver.FirstName = sanitizeHtml(FirstName.trim().charAt(0).toUpperCase() + FirstName.trim().slice(1).toLowerCase());
//     driver.LastName = sanitizeHtml(LastName.trim().charAt(0).toUpperCase() + LastName.trim().slice(1).toLowerCase());
//     driver.password = password.trim();
//     driver.phoneNumber = phoneNumber;
//     driver.DateOfBirth = DateOfBirth;
//     driver.Gender = Gender;
//     driver.licenseNumber = licenseNumber;
//     driver.drivingLicense = {
//       issueDate: drivingLicense.issueDate,
//       expiryDate: drivingLicense.expiryDate,
//       frontsideImage: frontsideImageUrl,
//       backsideImage: backsideImageUrl
//     };
//     driver.currentAddress = currentAddress;
//     driver.permanentAddress = permanentAddress;
//     driver.emergencyContactNumber = emergencyContactNumber;
//     driver.bankDetails = bankDetails;
//     driver.vehicleDetails = vehicleDetails;

//     await driver.save();

//     logger.info('Driver registered successfully', { driverId: driver._id, email: email.trim().toLowerCase() });
//     return res.status(201).json({
//       status: 'success',
//       message: 'Driver registered successfully. Awaiting admin verification.',
//       data: { driverId: driver._id, email: driver.email }
//     });
//   } catch (error) {
//     logger.error('Driver registration error', { error: error.message, email: req.body.email });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// const uploadImages = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed for image upload', { errors: errors.array(), driverId: req.user?._id });
//       return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
//     }

//     const driverId = req.user._id;
//     const { picture, frontsideImage, backsideImage } = req.files;

//     const updates = {};

//     if (picture) {
//       updates.picture = await uploadToCloudinary(picture[0].buffer, 'profile', driverId);
//     }
//     if (frontsideImage) {
//       updates['drivingLicense.frontsideImage'] = await uploadToCloudinary(frontsideImage[0].buffer, 'license_front', driverId);
//     }
//     if (backsideImage) {
//       updates['drivingLicense.backsideImage'] = await uploadToCloudinary(backsideImage[0].buffer, 'license_back', driverId);
//     }

//     if (Object.keys(updates).length === 0) {
//       logger.warn('No images provided for upload', { driverId });
//       return res.status(400).json({ status: 'error', message: 'At least one image is required' });
//     }

//     const driver = await Driver.findByIdAndUpdate(
//       driverId,
//       { $set: updates },
//       { new: true, select: '_id picture drivingLicense.frontsideImage drivingLicense.backsideImage' }
//     );

//     if (!driver) {
//       logger.warn('Driver not found for image upload', { driverId });
//       return res.status(404).json({ status: 'error', message: 'Driver not found' });
//     }

//     logger.info('Images uploaded successfully', { driverId, updates });
//     return res.status(200).json({
//       status: 'success',
//       message: 'Images uploaded successfully',
//       data: {
//         driverId: driver._id,
//         picture: driver.picture,
//         frontsideImage: driver.drivingLicense.frontsideImage,
//         backsideImage: driver.drivingLicense.backsideImage
//       }
//     });
//   } catch (error) {
//     logger.error('Image upload error', { driverId: req.user?._id, error: error.message });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// module.exports = { verifyEmail, verifyDriverOtp, registerDriver, uploadImages };

