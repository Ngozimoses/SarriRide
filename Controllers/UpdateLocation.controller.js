
/**THIS FILE CONTAINS THE REAL TIME IMPLEMENTATION OF SOCKET.IO FOR DRIVER LOCATION FOR LIVE UPDATE WHICH 
 * IS CALLED setupSocketIO WHILE THE API CONVENTION METHOD IS CALLED updateDriverLocation, PLEASE ENSURE NOT TO CONFUSE BOTH
 * 
 */
const { validationResult } = require('express-validator');
const Driver = require('../models/Driver');
const winston = require('winston');
// ADDED FOR SOCKET.IO
const { check } = require('express-validator');

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
      if (timeSinceLastUpdate < MIN_UPDATE_INTERVAL_SECONDS) {
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

// ADDED FOR SOCKET.IO FOR LIVE UPDATE IMPLEMENTATION 
const handleSocketUpdateLocation = async (socket, data, callback) => {
  try {
    // Validate input
    await Promise.all([
      check('latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid latitude (-90 to 90) required').run({ body: data }),
      check('longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid longitude (-180 to 180) required').run({ body: data }),
      check('availabilityStatus')
        .optional()
        .isIn(['available', 'unavailable', 'on_trip'])
        .withMessage('Invalid availability status')
        .run({ body: data })
    ]);

    const errors = validationResult({ body: data });
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for driver location update (Socket.IO)', { errors: errors.array(), driverId: socket.user._id });
      return callback({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { latitude, longitude, availabilityStatus } = data;
    const driverId = socket.user._id;

    // Check if update is too frequent
    const driver = await Driver.findById(driverId).select('lastLocationUpdate');
    if (driver && driver.lastLocationUpdate) {
      const timeSinceLastUpdate = (new Date() - driver.lastLocationUpdate) / 1000;
      if (timeSinceLastUpdate >  MIN_UPDATE_INTERVAL_SECONDS) {
        logger.warn('Location update too frequent (Socket.IO)', { driverId, timeSinceLastUpdate });
        return callback({ status: 'error', message: 'Location update too frequent, please wait' });
      }
    }

    // Update location and status
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
      logger.warn('Driver not found for location update (Socket.IO)', { driverId });
      return callback({ status: 'error', message: 'Driver not found' });
    }

    logger.info('Driver location updated successfully (Socket.IO)', { driverId, latitude, longitude, availabilityStatus });
    callback({
      status: 'success',
      message: 'Location updated successfully',
      data: {
        location: updatedDriver.location,
        availabilityStatus: updatedDriver.availabilityStatus,
        lastLocationUpdate: updatedDriver.lastLocationUpdate
      }
    });
  } catch (error) {
    logger.error('Error updating driver location (Socket.IO)', { error: error.message, driverId: socket.user._id });
    callback({ status: 'error', message: 'An unexpected error occurred' });
  }
};

// ADDED FOR SOCKET.IO
const setupSocketIO = (io) => {
  io.on('connection', (socket) => {
    logger.info('Driver connected (Socket.IO)', { driverId: socket.user._id });

    socket.on('updateLocation', (data, callback) => {
      handleSocketUpdateLocation(socket, data, callback);
    });

    socket.on('disconnect', () => {
      logger.info('Driver disconnected (Socket.IO)', { driverId: socket.user._id });
    });
  });
};

module.exports = { updateDriverLocation, setupSocketIO };


// const { validationResult } = require('express-validator');
// const Driver = require('../models/Driver');
// const winston = require('winston');

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

// const MIN_UPDATE_INTERVAL_SECONDS = 5; // Prevent excessive updates

// const updateDriverLocation = async (req, res) => {
//   try {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed for driver location update', { errors: errors.array(), driverId: req.user?._id });
//       return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
//     }

//     const { latitude, longitude, availabilityStatus } = req.body;
//     const driverId = req.user._id; // From authMiddleware

//     // Check if update is too frequent
//     const driver = await Driver.findById(driverId).select('lastLocationUpdate');
//     if (driver && driver.lastLocationUpdate) {
//       const timeSinceLastUpdate = (new Date() - driver.lastLocationUpdate) / 1000;
//       if (timeSinceLastUpdate > MIN_UPDATE_INTERVAL_SECONDS) {
//         logger.warn('Location update too frequent', { driverId, timeSinceLastUpdate });
//         return res.status(429).json({ status: 'error', message: 'Location update too frequent, please wait' });
//       }
//     }

//     // Update location and status (if provided)
//     const updateFields = {
//       location: {
//         type: 'Point',
//         coordinates: [longitude, latitude]
//       },
//       lastLocationUpdate: new Date()
//     };

//     if (availabilityStatus && ['available', 'unavailable', 'on_trip'].includes(availabilityStatus)) {
//       updateFields.availabilityStatus = availabilityStatus;
//     }

//     const updatedDriver = await Driver.findByIdAndUpdate(
//       driverId,
//       { $set: updateFields },
//       { new: true, select: 'location availabilityStatus lastLocationUpdate' }
//     );

//     if (!updatedDriver) {
//       logger.warn('Driver not found for location update', { driverId });
//       return res.status(404).json({ status: 'error', message: 'Driver not found' });
//     }

//     logger.info('Driver location updated successfully', { driverId, latitude, longitude, availabilityStatus });
//     return res.status(200).json({
//       status: 'success',
//       message: 'Location updated successfully',
//       data: {
//         location: updatedDriver.location,
//         availabilityStatus: updatedDriver.availabilityStatus,
//         lastLocationUpdate: updatedDriver.lastLocationUpdate
//       }
//     });
//   } catch (error) {
//     logger.error('Error updating driver location', { error: error.message, driverId: req.user?._id });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// module.exports = { updateDriverLocation };
