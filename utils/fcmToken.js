const express = require('express');
const mongoose = require('mongoose'); // Added missing import
const Driver = require('../models/Driver');
const Client = require('../models/Client');
const { validationResult } = require('express-validator');
const winston = require('winston');
const { rateLimit } = require('express-rate-limit'); // For endpoint-specific rate limiting

// Enhanced logging with rotation and error file
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Rate limit for this endpoint (e.g., 100 requests per hour per IP)
const tokenUpdateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100,
  message: { status: 'error', message: 'Too many requests, please try again later' }
});

const updateFcmToken = [
  tokenUpdateLimiter,
  /**
   * Updates the FCM token for a driver or rider.
   * @param {Object} req - Express request object
   * @param {Object} req.body - Request body with fcmToken and userId
   * @param {string} req.body.fcmToken - The FCM token from the client
   * @param {string} req.body.userId - The ObjectId of the user
   * @param {Object} req.user - Authenticated user object with role
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with status and message
   */
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        logger.warn('Validation failed for FCM token update', { errors: errors.array(), userId: req.user?._id });
        return res.status(400).json({ status: 'error', message: 'Invalid request', errors: errors.array() });
      }

      const { fcmToken, userId } = req.body;
      const userRole = req.user?.role;

      // Validate role and token
      if (!userRole || !['driver', 'rider'].includes(userRole)) {
        return res.status(400).json({ status: 'error', message: 'Invalid role' });
      }
      if (!fcmToken || !userId || !mongoose.Types.ObjectId.isValid(userId) || !/^[a-zA-Z0-9\-_]+:[\w\-]+$/i.test(fcmToken) || fcmToken.length > 500) {
        logger.warn('Invalid FCM token or userId', { userId, userRole });
        return res.status(400).json({ status: 'error', message: 'Invalid token or userId' });
      }

      let user;
      if (userRole === 'driver') {
        user = await Driver.findByIdAndUpdate(userId, { fcmToken }, { new: true, runValidators: true });
      } else if (userRole === 'rider') {
        user = await Client.findByIdAndUpdate(userId, { fcmToken }, { new: true, runValidators: true });
      } else {
        return res.status(403).json({ status: 'error', message: 'Unauthorized role' });
      }

      if (!user) {
        logger.warn('User not found for FCM token update', { userId, userRole });
        return res.status(404).json({ status: 'error', message: 'User not found' });
      }

      logger.info('FCM token updated successfully', { userId: user._id.toString(), userRole }); // Use _id to avoid logging full object
      return res.status(200).json({ status: 'success', message: 'FCM token updated' });
    } catch (err) {
      logger.error('Error updating FCM token', { error: err.message, userId: req.user?._id?.toString() });
      return res.status(500).json({ status: 'error', message: err.message || 'An unexpected error occurred' });
    }
  }
];

module.exports = { updateFcmToken };
