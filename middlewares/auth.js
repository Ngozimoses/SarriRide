// const jwt = require('jsonwebtoken');
// const winston = require('winston');
// const { validationResult } = require('express-validator');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');
// const { v4: uuidv4 } = require('uuid');
// const Client = require('../models/Client');
// const Driver = require('../models/Driver');
// const Admin = require('../models/Admin');
// const Rider = require('../models/Rider');
// const redis = require('../Config/redis');
// const { decrypt } = require('../utils/encryptDecrypt');
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
//   ALLOWED_ROLES: ['client', 'driver', 'admin', 'rider'],
//   JWT_ACCESS_TOKEN_EXPIRY: '15m',
//   OTP_EXPIRY_MS: 3600000,
//   RESET_TOKEN_EXPIRY_MS: 15 * 60 * 1000,
//    REDIS_KEY_PREFIX: 'auth:', 
// };

// const validateEnv = () => {
//   if (!process.env.JWT_SECRET) {
//     logger.error('JWT_SECRET is not set');
//     throw new Error('JWT_SECRET is required');
//   }
//   if (!process.env.ENCRYPTION_KEY) {
//     logger.error('COOKIE_ENCRYPTION_KEY is not set');
//     throw new Error('COOKIE_ENCRYPTION_KEY is required');
//   }
//   if (!process.env.BACKEND_URL) {
//     logger.error('BACKEND_URL is not set');
//     throw new Error('BACKEND_URL is required');
//   }
// };

// const modelMap = {
//   client: Client,
//   driver: Driver,
//   admin: Admin,
//   rider: Rider,
// };

// const authMiddleware = (requiredRole = null) => {
//   return async (req, res, next) => {
//     try {
//       const authHeader = req.headers['authorization'];
//       if (!authHeader || !authHeader.startsWith('Bearer ')) {
//         logger.warn('No valid Authorization header provided');
//         return res.status(401).json({ status: 'error', message: 'Unauthorized - No token provided' });
//       }

//       const token = authHeader.split(' ')[1];
//       if (!token) {
//         logger.warn('Token missing in Authorization header');
//         return res.status(401).json({ status: 'error', message: 'Unauthorized - No token provided' });
//       }

//       let decryptedToken;
//       try {
//         decryptedToken = decrypt(token);
//       } catch (error) {
//         logger.warn('Failed to decrypt token', { error: error.message });
//         return res.status(401).json({ status: 'error', message: 'Unauthorized - Invalid token format' });
//       }

//       const isBlacklisted = await redis.get(`blacklist:${decryptedToken}`);
//       if (isBlacklisted) {
//         logger.warn('Blacklisted token used');
//         return res.status(401).json({ status: 'error', message: 'Unauthorized - Token revoked' });
//       }

//       const decoded = jwt.verify(decryptedToken, process.env.JWT_SECRET);
//       logger.debug('Token decoded', {
//         userId: decoded.id,
//         role: decoded.role,
//         isAdminSession: decoded.isAdminSession,
//         expiry: new Date(decoded.exp * 1000),
//       });

//       const Model = modelMap[decoded.role];
//       if (!Model) {
//         logger.warn('Invalid role in token', { role: decoded.role });
//         return res.status(401).json({ status: 'error', message: 'Unauthorized - Invalid role' });
//       }

//       let user;
//       const cacheKey = `user:${decoded.id}:${decoded.role}`;
//       const cachedUser = await redis.get(cacheKey);
//       if (cachedUser) {
//         user = JSON.parse(cachedUser);
//       } else {
//         const selectFields = decoded.role === 'driver'
//           ? '_id email FirstName LastName role picture isVerified adminVerified'
//           : '_id email FirstName LastName role picture isVerified';
//         user = await Model.findById(decoded.id).select(selectFields).lean();
//         if (user) {
//           await redis.set(cacheKey, JSON.stringify(user), 'EX', 3600); // Cache for 1 hour
//         }
//       }

//       if (!user) {
//         logger.warn('User not found for token', { userId: decoded.id, role: decoded.role });
//         return res.status(401).json({ status: 'error', message: 'Unauthorized - User not found' });
//       }

//       if (user.role !== decoded.role) {
//         logger.warn('Token role mismatch', { userId: user._id, tokenRole: decoded.role, userRole: user.role });
//         return res.status(401).json({ status: 'error', message: 'Unauthorized - Invalid token role' });
//       }

//       if (!CONFIG.ALLOWED_ROLES.includes(user.role)) {
//         logger.warn('Invalid user role', { userId: user._id, role: user.role });
//         return res.status(403).json({ status: 'error', message: `Forbidden - Valid role (${CONFIG.ALLOWED_ROLES.join(', ')}) required` });
//       }

//       // if (user.role === 'driver' && !user.adminVerified && process.env.NODE_ENV !== 'test') {
//       //   logger.warn('Driver not approved by admin', { userId: user._id });
//       //   return res.status(403).json({ status: 'error', message: 'Forbidden - Account awaiting admin approval' });
//       // }

//       const isAdminSession = decoded.isAdminSession || false;
//       if (requiredRole === 'admin' && (!isAdminSession || user.role !== 'admin')) {
//         logger.warn('Admin session or role required for admin route', { userId: user._id, role: user.role });
//         return res.status(403).json({ status: 'error', message: 'Forbidden - Admin role and session required' });
//       }

//       req.user = {
//         _id: user._id,
//         email: user.email,
//         name: user.name || `${user.FirstName} ${user.LastName}`.trim(),
//         picture: user.picture,
//         role: user.role,
//         isVerified: user.isVerified,
//         isAdminSession,
//         ...(user.role === 'driver' && { adminVerified: user.adminVerified }),
//       };

//       if (user.role === 'client') {
//         const client = await Client.findOne({ userId: user._id }).lean();
//         req.user.client = client || null;
//         logger.info('Client profile attached to request', { userId: user._id, clientId: client ? client._id : null });
//       }

//       if (requiredRole) {
//         const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
//         if (!requiredRoles.every(role => CONFIG.ALLOWED_ROLES.includes(role))) {
//           logger.warn('Invalid required role specified', { requiredRoles });
//           return res.status(500).json({ status: 'error', message: 'Server configuration error - Invalid required role' });
//         }
//         if (!requiredRoles.includes(req.user.role)) {
//           logger.warn('Role access denied', {
//             userId: user._id,
//             userRole: req.user.role,
//             requiredRoles,
//           });
//           return res.status(403).json({
//             status: 'error',
//             message: `Forbidden - ${requiredRoles.join(' or ')} role required`,
//           });
//         }
//       }

//       next();
//     } catch (error) {
//       let statusCode = 401;
//       let response = { status: 'error', message: 'Unauthorized - Invalid token' };

//       if (error.name === 'TokenExpiredError') {
//         response.message = 'Session expired - Please log in again';
//       } else if (error.name === 'JsonWebTokenError') {
//         response.message = 'Unauthorized - Invalid token';
//       }

//       logger.warn('Authentication error', { error: error.message, tokenSource: 'Authorization header' });
//       return res.status(statusCode).json(response);
//     }
//   };
// };


const jwt = require('jsonwebtoken');
const winston = require('winston');
const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const Client = require('../models/Client');
const Driver = require('../models/Driver');
const Admin = require('../models/Admin');
const Rider = require('../models/Rider');
const redis = require('../Config/redis');
const { decrypt } = require('../utils/encryptDecrypt');
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
  ALLOWED_ROLES: ['client', 'driver', 'admin', 'rider'],
  JWT_ACCESS_TOKEN_EXPIRY: '15m',
  OTP_EXPIRY_MS: 3600000,
  RESET_TOKEN_EXPIRY_MS: 15 * 60 * 1000,
  REDIS_KEY_PREFIX: 'auth:', 
};

const validateEnv = () => {
  if (!process.env.JWT_SECRET) {
    logger.error('JWT_SECRET is not set');
    throw new Error('JWT_SECRET is required');
  }
  if (!process.env.ENCRYPTION_KEY) {
    logger.error('COOKIE_ENCRYPTION_KEY is not set');
    throw new Error('COOKIE_ENCRYPTION_KEY is required');
  }
  if (!process.env.BACKEND_URL) {
    logger.error('BACKEND_URL is not set');
    throw new Error('BACKEND_URL is required');
  }
};

const modelMap = {
  client: Client,
  driver: Driver,
  admin: Admin,
  rider: Rider,
};

const authMiddleware = (requiredRole = null) => {
  return async (req, res, next) => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn('No valid Authorization header provided');
        return res.status(401).json({ status: 'error', message: 'Unauthorized - No token provided' });
      }

      const token = authHeader.split(' ')[1];
      if (!token) {
        logger.warn('Token missing in Authorization header');
        return res.status(401).json({ status: 'error', message: 'Unauthorized - No token provided' });
      }

      let decryptedToken;
      try {
        decryptedToken = decrypt(token);
      } catch (error) {
        logger.warn('Failed to decrypt token', { error: error.message });
        return res.status(401).json({ status: 'error', message: 'Unauthorized - Invalid token format' });
      }

      const isBlacklisted = await redis.get(`blacklist:${decryptedToken}`);
      if (isBlacklisted) {
        logger.warn('Blacklisted token used');
        return res.status(401).json({ status: 'error', message: 'Unauthorized - Token revoked' });
      }

      const decoded = jwt.verify(decryptedToken, process.env.JWT_SECRET);
      logger.debug('Token decoded', {
        userId: decoded.id,
        role: decoded.role,
        isAdminSession: decoded.isAdminSession,
        expiry: new Date(decoded.exp * 1000),
      });

      const Model = modelMap[decoded.role];
      if (!Model) {
        logger.warn('Invalid role in token', { role: decoded.role });
        return res.status(401).json({ status: 'error', message: 'Unauthorized - Invalid role' });
      }

      let user;
      const cacheKey = `user:${decoded.id}:${decoded.role}`;
      const cachedUser = await redis.get(cacheKey);
      if (cachedUser) {
        user = JSON.parse(cachedUser);
      } else {
        const selectFields = decoded.role === 'driver'
          ? '_id email FirstName LastName role picture isVerified adminVerified'
          : '_id email FirstName LastName role picture isVerified';
        user = await Model.findById(decoded.id).select(selectFields).lean();
        if (user) {
          await redis.set(cacheKey, JSON.stringify(user), 'EX', 3600); // Cache for 1 hour
        }
      }

      if (!user) {
        logger.warn('User not found for token', { userId: decoded.id, role: decoded.role });
        return res.status(401).json({ status: 'error', message: 'Unauthorized - User not found' });
      }

      if (user.role !== decoded.role) {
        logger.warn('Token role mismatch', { userId: user._id, tokenRole: decoded.role, userRole: user.role });
        return res.status(401).json({ status: 'error', message: 'Unauthorized - Invalid token role' });
      }

      if (!CONFIG.ALLOWED_ROLES.includes(user.role)) {
        logger.warn('Invalid user role', { userId: user._id, role: user.role });
        return res.status(403).json({ status: 'error', message: `Forbidden - Valid role (${CONFIG.ALLOWED_ROLES.join(', ')}) required` });
      }

      // if (user.role === 'driver' && !user.adminVerified && process.env.NODE_ENV !== 'test') {
      //   logger.warn('Driver not approved by admin', { userId: user._id });
      //   return res.status(403).json({ status: 'error', message: 'Forbidden - Account awaiting admin approval' });
      // }

      const isAdminSession = decoded.isAdminSession || false;
      if (requiredRole === 'admin' && (!isAdminSession || user.role !== 'admin')) {
        logger.warn('Admin session or role required for admin route', { userId: user._id, role: user.role });
        return res.status(403).json({ status: 'error', message: 'Forbidden - Admin role and session required' });
      }

      req.user = {
        _id: user._id,
        email: user.email,
        name: user.name || `${user.FirstName} ${user.LastName}`.trim(),
        picture: user.picture,
        role: user.role,
        isVerified: user.isVerified,
        isAdminSession,
        ...(user.role === 'driver' && { adminVerified: user.adminVerified }),
      };

      if (user.role === 'client') {
        const client = await Client.findOne({ userId: user._id }).lean();
        req.user.client = client || null;
        logger.info('Client profile attached to request', { userId: user._id, clientId: client ? client._id : null });
      }

      if (requiredRole) {
        const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
        if (!requiredRoles.every(role => CONFIG.ALLOWED_ROLES.includes(role))) {
          logger.warn('Invalid required role specified', { requiredRoles });
          return res.status(500).json({ status: 'error', message: 'Server configuration error - Invalid required role' });
        }
        if (!requiredRoles.includes(req.user.role)) {
          logger.warn('Role access denied', {
            userId: user._id,
            userRole: req.user.role,
            requiredRoles,
          });
          return res.status(403).json({
            status: 'error',
            message: `Forbidden - ${requiredRoles.join(' or ')} role required`,
          });
        }
      }

      next();
    } catch (error) {
      let statusCode = 401;
      let response = { status: 'error', message: 'Unauthorized - Invalid token' };

      if (error.name === 'TokenExpiredError') {
        response.message = 'Session expired - Please log in again';
      } else if (error.name === 'JsonWebTokenError') {
        response.message = 'Unauthorized - Invalid token';
      }

      logger.warn('Authentication error', { error: error.message, tokenSource: 'Authorization header' });
      return res.status(statusCode).json(response);
    }
  };
};

// ADDED FOR SOCKET.IO
const authMiddlewareSocket = (requiredRole = null) => {
  return async (socket, next) => {
    try {
      // const token = socket.handshake.auth.token;
       const token = socket.handshake.auth.token || socket.handshake.query.token;
      if (!token) {
        logger.warn('No token provided for Socket.IO', { role: requiredRole });
        return next(new Error('Unauthorized - No token provided'));
      }

      let decryptedToken;
      try {
        decryptedToken = decrypt(token);
      } catch (error) {
        logger.warn('Failed to decrypt Socket.IO token', { error: error.message });
        return next(new Error('Unauthorized - Invalid token format'));
      }

      const isBlacklisted = await redis.get(`blacklist:${decryptedToken}`);
      if (isBlacklisted) {
        logger.warn('Blacklisted Socket.IO token used');
        return next(new Error('Unauthorized - Token revoked'));
      }

      const decoded = jwt.verify(decryptedToken, process.env.JWT_SECRET);
      logger.debug('Socket.IO token decoded', {
        userId: decoded.id,
        role: decoded.role,
        isAdminSession: decoded.isAdminSession,
      });

      const Model = modelMap[decoded.role];
      if (!Model) {
        logger.warn('Invalid role in Socket.IO token', { role: decoded.role });
        return next(new Error('Unauthorized - Invalid role'));
      }

      let user;
      const cacheKey = `user:${decoded.id}:${decoded.role}`;
      const cachedUser = await redis.get(cacheKey);
      if (cachedUser) {
        user = JSON.parse(cachedUser);
      } else {
        const selectFields = decoded.role === 'driver'
          ? '_id email FirstName LastName role picture isVerified adminVerified'
          : '_id email FirstName LastName role picture isVerified';
        user = await Model.findById(decoded.id).select(selectFields).lean();
        if (user) {
          await redis.set(cacheKey, JSON.stringify(user), 'EX', 3600); // Cache for 1 hour
        }
      }

      if (!user) {
        logger.warn('User not found for Socket.IO token', { userId: decoded.id, role: decoded.role });
        return next(new Error('Unauthorized - User not found'));
      }

      if (user.role !== decoded.role) {
        logger.warn('Socket.IO token role mismatch', { userId: user._id, tokenRole: decoded.role, userRole: user.role });
        return next(new Error('Unauthorized - Invalid token role'));
      }

      if (!CONFIG.ALLOWED_ROLES.includes(user.role)) {
        logger.warn('Invalid user role for Socket.IO', { userId: user._id, role: user.role });
        return next(new Error(`Forbidden - Valid role (${CONFIG.ALLOWED_ROLES.join(', ')}) required`));
      }

      // if (user.role === 'driver' && !user.adminVerified && process.env.NODE_ENV !== 'test') {
      //   logger.warn('Driver not approved by admin for Socket.IO', { userId: user._id });
      //   return next(new Error('Forbidden - Account awaiting admin approval'));
      // }

      const isAdminSession = decoded.isAdminSession || false;
      if (requiredRole === 'admin' && (!isAdminSession || user.role !== 'admin')) {
        logger.warn('Admin session or role required for Socket.IO', { userId: user._id, role: user.role });
        return next(new Error('Forbidden - Admin role and session required'));
      }

      socket.user = {
        _id: user._id,
        email: user.email,
        name: user.name || `${user.FirstName} ${user.LastName}`.trim(),
        picture: user.picture,
        role: user.role,
        isVerified: user.isVerified,
        isAdminSession,
        ...(user.role === 'driver' && { adminVerified: user.adminVerified }),
      };

      if (requiredRole) {
        const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
        if (!requiredRoles.every(role => CONFIG.ALLOWED_ROLES.includes(role))) {
          logger.warn('Invalid required role specified for Socket.IO', { requiredRoles });
          return next(new Error('Server configuration error - Invalid required role'));
        }
        if (!requiredRoles.includes(socket.user.role)) {
          logger.warn('Socket.IO role access denied', {
            userId: user._id,
            userRole: socket.user.role,
            requiredRoles,
          });
          return next(new Error(`Forbidden - ${requiredRoles.join(' or ')} role required`));
        }
      }

      next();
    } catch (error) {
      let message = 'Unauthorized - Invalid token';
      if (error.name === 'TokenExpiredError') {
        message = 'Session expired - Please log in again';
      } else if (error.name === 'JsonWebTokenError') {
        message = 'Unauthorized - Invalid token';
      }

      logger.warn('Socket.IO authentication error', { error: error.message, tokenSource: 'Socket.IO handshake' });
      return next(new Error(message));
    }
  };
};


const ForgotPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during forgot password', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }
    const { email, role } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedRole = role.trim().toLowerCase();

    if (!CONFIG.ALLOWED_ROLES.includes(sanitizedRole)) {
      logger.warn('Invalid role in forgot password request', { role: sanitizedRole });
      return res.status(400).json({ status: 'error', message: `Valid role (${CONFIG.ALLOWED_ROLES.join(', ')}) required` });
    }

    const Model = modelMap[sanitizedRole];
    const user = await Model.findOne({ email: sanitizedEmail, role: sanitizedRole });

    if (!user || !user.password) {
      logger.info('Forgot password attempt for non-existent or OAuth account', { email: sanitizedEmail, role: sanitizedRole });
      return res.status(200).json({ status: 'success', message: 'If an account exists, a reset code has been sent.' });
    }

    const resetToken = crypto.randomBytes(64).toString('hex');
    const salt = crypto.randomBytes(16);
    const resetTokenId = uuidv4();
    const hashedResetToken = crypto.pbkdf2Sync(resetToken, salt, 10000, 64, 'sha512').toString('hex');
    const resetCode = crypto.randomInt(100000, 999999).toString(); // 6-digit code for email

    user.resetToken = hashedResetToken;
    user.resetTokenSalt = salt.toString('hex');
    user.resetTokenId = resetTokenId;
    user.resetTokenExpires = Date.now() + CONFIG.RESET_TOKEN_EXPIRY_MS;
    user.resetCode = resetCode;

    await user.save();

    const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}reset:${resetTokenId}`;
    await redis.set(cacheKey, JSON.stringify({ resetCode, email: sanitizedEmail, role: sanitizedRole }), 'EX', Math.floor(CONFIG.RESET_TOKEN_EXPIRY_MS / 1000));

    try {
      await sendEmail(
        sanitizedEmail,
        'Password Reset Code',
        `Your password reset code is: ${resetCode}\nExpires in 15 minutes.`
      );
    } catch (emailErr) {
      logger.error('Failed to send password reset email', { error: emailErr.message, email: sanitizedEmail });
      return res.status(500).json({ status: 'error', message: 'Failed to send reset code' });
    }

    logger.info('Password reset code sent', { email: sanitizedEmail, role: sanitizedRole });
    return res.status(200).json({
      status: 'success',
      message: 'Reset code sent to email.',
      data: { resetTokenId } // Return tokenId for mobile app
    });
  } catch (error) {
    logger.error('Forgot password error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const UpdatePassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during update password', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { resetTokenId, resetCode, password, role } = req.body;
    const sanitizedRole = role.trim().toLowerCase();

    if (!CONFIG.ALLOWED_ROLES.includes(sanitizedRole)) {
      logger.warn('Invalid role in update password request', { role: sanitizedRole });
      return res.status(400).json({ status: 'error', message: `Valid role (${CONFIG.ALLOWED_ROLES.join(', ')}) required` });
    }

    const Model = modelMap[sanitizedRole];
    const user = await Model.findOne({
      resetTokenId,
      resetTokenExpires: { $gt: Date.now() },
      role: sanitizedRole,
    });

    if (!user || !user.resetCode || user.resetCode !== resetCode) {
      logger.warn('Invalid or expired password reset code', { resetTokenId, role: sanitizedRole });
      return res.status(400).json({ status: 'error', message: 'Invalid or expired reset code' });
    }

    // Clear Redis cache
    const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}reset:${resetTokenId}`;
    await redis.del(cacheKey);

    user.password = password;
    user.resetToken = undefined;
    user.resetTokenSalt = undefined;
    user.resetTokenId = undefined;
    user.resetTokenExpires = undefined;
    user.resetCode = undefined;

    await user.save();

    // Update user cache
    const userCacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${user.email}:${sanitizedRole}`;
    await redis.set(userCacheKey, JSON.stringify(user), 'EX', CONFIG.USER_CACHE_TTL || 3600);

    logger.info('Password updated successfully', { userId: user._id, role: sanitizedRole });
    return res.status(200).json({ status: 'success', message: 'Password updated successfully' });
  } catch (error) {
    logger.error('Update password error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};


const VerifyOtp = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed during OTP verification', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { email, otp, role } = req.body;
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedRole = role ? role.trim().toLowerCase() : undefined;

    if (!sanitizedRole || !CONFIG.ALLOWED_ROLES.includes(sanitizedRole)) {
      logger.warn('Invalid or missing role in OTP verification request', { role: sanitizedRole });
      return res.status(400).json({ status: 'error', message: `Valid role (${CONFIG.ALLOWED_ROLES.join(', ')}) required` });
    }

    const Model = modelMap[sanitizedRole];
    if (!Model) {
      logger.warn('Invalid model for role', { role: sanitizedRole });
      return res.status(400).json({ status: 'error', message: 'Invalid role' });
    }

    const user = await Model.findOne({ email: sanitizedEmail, role: sanitizedRole });
    if (!user) {
      logger.warn('User not found for OTP verification', { email: sanitizedEmail, role: sanitizedRole });
      return res.status(400).json({ status: 'error', message: 'User not found' });
    }

    const otpKey = `${CONFIG.REDIS_KEY_PREFIX}otp:${user._id}`;
    const cachedOtp = await redis.get(otpKey);
    if (cachedOtp && cachedOtp === otp && user.resetTokenExpires > Date.now()) {
      user.isVerified = true;
      user.resetToken = undefined;
      user.resetTokenExpires = undefined;
      await user.save();
      await redis.del(otpKey);
      await redis.del(`${CONFIG.REDIS_KEY_PREFIX}user:${user._id}:${sanitizedRole}`); // Invalidate user cache
    } else {
      logger.warn('Invalid or expired OTP', { email: sanitizedEmail, role: sanitizedRole });
      return res.status(400).json({ status: 'error', message: 'Invalid or expired OTP' });
    }

    logger.info('OTP verification successful', { userId: user._id, email: sanitizedEmail, role: sanitizedRole });
    return res.status(200).json({
      status: 'success',
      message: 'Verification successful',
      data: {
        user: {
          _id: user._id,
          email: user.email,
          role: user.role,
          isVerified: user.isVerified,
        },
      },
    });
  } catch (error) {
    logger.error('OTP verification error', { error: error.message, email: req.body.email });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

validateEnv();

module.exports = { authMiddleware, ForgotPassword, UpdatePassword, VerifyOtp , authMiddlewareSocket };
