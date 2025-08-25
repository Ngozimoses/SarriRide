
const { validationResult } = require('express-validator');
const { getDistanceKm, calculatePrices } = require('../utils/rideUtils');
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

const calculateRidePrice = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for ride price calculation', { errors: errors.array(), userId: req.user?._id });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { currentLocation, destination } = req.body;

    if (!currentLocation || !destination ||
        typeof currentLocation.latitude !== 'number' ||
        typeof currentLocation.longitude !== 'number' ||
        typeof destination.latitude !== 'number' ||
        typeof destination.longitude !== 'number') {
      logger.warn('Invalid coordinates provided', { currentLocation, destination, userId: req.user?._id });
      return res.status(400).json({ status: 'error', message: 'Valid latitude and longitude required' });
    }

    const userId = req.user?._id?.toString() || 'anonymous';
    const distanceKm = await getDistanceKm(currentLocation, destination, userId);
    const prices = await calculatePrices(distanceKm, userId);

    logger.info('Ride price calculated successfully', { distanceKm, prices, userId });
    return res.status(200).json({
      status: 'success',
      message: 'Ride prices calculated',
      data: { distanceKm, prices }
    });
  } catch (error) {
    logger.error('Ride price calculation error', { error: error.message, userId: req.user?._id });
    return res.status(500).json({ status: 'error', message: error.message || 'An unexpected error occurred' });
  }
};

// Middleware to support query parameters
const mapQueryToBody = (req, res, next) => {
  const { currentLat, currentLng, destLat, destLng } = req.query;
  if (currentLat && currentLng && destLat && destLng) {
    req.body = {
      currentLocation: {
        latitude: parseFloat(currentLat),
        longitude: parseFloat(currentLng),
      },
      destination: {
        latitude: parseFloat(destLat),
        longitude: parseFloat(destLng),
      },
    };
  }
  next();
};
module.exports = { calculateRidePrice, mapQueryToBody };
