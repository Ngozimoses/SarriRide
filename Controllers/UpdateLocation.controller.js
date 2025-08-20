
const { validationResult } = require('express-validator');
const Driver = require('../models/Driver');
const winston = require('winston');

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

const MIN_UPDATE_INTERVAL_SECONDS = 5; // Prevent excessive updates

const updateDriverLocation = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for driver location update', { errors: errors.array(), driverId: req.user?._id });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { latitude, longitude, availabilityStatus } = req.body;
    const driverId = req.user._id; // From authMiddleware

    // Check if update is too frequent
    const driver = await Driver.findById(driverId).select('lastLocationUpdate');
    if (driver && driver.lastLocationUpdate) {
      const timeSinceLastUpdate = (new Date() - driver.lastLocationUpdate) / 1000;
      if (timeSinceLastUpdate > MIN_UPDATE_INTERVAL_SECONDS) {
        logger.warn('Location update too frequent', { driverId, timeSinceLastUpdate });
        return res.status(429).json({ status: 'error', message: 'Location update too frequent, please wait' });
      }
    }

    // Update location and status (if provided)
    const updateFields = {
      location: {
        type: 'Point',
        coordinates: [longitude, latitude]
      },
      lastLocationUpdate: new Date()
    };

    if (availabilityStatus && ['available', 'unavailable', 'on_trip'].includes(availabilityStatus)) {
      updateFields.availabilityStatus = availabilityStatus;
    }

    const updatedDriver = await Driver.findByIdAndUpdate(
      driverId,
      { $set: updateFields },
      { new: true, select: 'location availabilityStatus lastLocationUpdate' }
    );

    if (!updatedDriver) {
      logger.warn('Driver not found for location update', { driverId });
      return res.status(404).json({ status: 'error', message: 'Driver not found' });
    }

    logger.info('Driver location updated successfully', { driverId, latitude, longitude, availabilityStatus });
    return res.status(200).json({
      status: 'success',
      message: 'Location updated successfully',
      data: {
        location: updatedDriver.location,
        availabilityStatus: updatedDriver.availabilityStatus,
        lastLocationUpdate: updatedDriver.lastLocationUpdate
      }
    });
  } catch (error) {
    logger.error('Error updating driver location', { error: error.message, driverId: req.user?._id });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

module.exports = { updateDriverLocation };
