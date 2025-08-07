const { check, validationResult } = require('express-validator');
const Driver = require('../models/Driver');
const Client = require('../models/Client'); // Added import for Client model
const winston = require('winston');
const { uploadToCloudinary } = require('../Config/cloudinary');
const crypto = require('crypto');
const redis = require('../Config/redis');
const sendEmail = require('../utils/sendMail');
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

    // Check if email is already registered in Client collection
    const existingClient = await Client.findOne({ email: sanitizedEmail }).lean();
    if (existingClient) {
      logger.warn('Email already registered as a client', { email: sanitizedEmail });
      return res.status(400).json({ status: 'error', message: 'Email already registered as a client' });
    }

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

    // Check if email is verified
    const driver = await Driver.findOne({ email: email.trim().toLowerCase() });
    if (!driver || !driver.isVerified) {
      logger.warn('Email not verified for registration', { email: email.trim().toLowerCase() });
      return res.status(400).json({ status: 'error', message: 'Email must be verified before registration' });
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

