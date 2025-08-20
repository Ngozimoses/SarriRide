
const { validationResult } = require('express-validator');
const Driver = require('../models/Driver');
const { getDistanceKm, calculatePrices } = require('../utils/rideUtils');
const redis = require('../Config/redis');
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

const MAX_SEARCH_RADIUS_METERS = 10000; // 10km radius for nearby drivers
const AVAILABILITY_CACHE_TTL_SECONDS = 30; // Cache driver counts for 30 seconds

const checkAvailableDrivers = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for available drivers check', { errors: errors.array(), userId: req.user?._id });
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
    const cacheKey = `drivers:near:${currentLocation.latitude}:${currentLocation.longitude}`;
    
    // Check Redis cache for driver availability
    let availableByCategory = await redis.get(cacheKey);
    if (availableByCategory) {
      availableByCategory = JSON.parse(availableByCategory);
      logger.info('Driver availability retrieved from cache', { cacheKey, userId });
    } else {
      // Geospatial query to find nearby available drivers
      const availableDriversAgg = await Driver.aggregate([
        {
          $geoNear: {
            near: { type: 'Point', coordinates: [currentLocation.longitude, currentLocation.latitude] },
            distanceField: 'dist.calculated',
            maxDistance: MAX_SEARCH_RADIUS_METERS,
            query: { availabilityStatus: 'available', adminVerified: true }, // Only verified, available drivers
            spherical: true
          }
        },
        {
          $group: {
            _id: '$category',
            drivers: { $push: { _id: '$_id', name: { $concat: ['$FirstName', ' ', '$LastName'] }, location: '$location' } },
            count: { $sum: 1 }
          }
        }
      ]);

      availableByCategory = availableDriversAgg.reduce((acc, item) => {
        acc[item._id] = { count: item.count, drivers: item.drivers };
        return acc;
      }, {});

      // Cache for 30 seconds
      await redis.set(cacheKey, JSON.stringify(availableByCategory), 'EX', AVAILABILITY_CACHE_TTL_SECONDS);
      logger.info('Driver availability cached', { cacheKey, availableByCategory, userId });
    }

    const distanceKm = await getDistanceKm(currentLocation, destination, userId);
    const prices = await calculatePrices(distanceKm, userId);

    // Combine prices with availability
    const categoryDetails = {};
    Object.keys(prices).forEach(category => {
      categoryDetails[category] = {
        ...prices[category],
        availableDriversCount: availableByCategory[category]?.count || 0,
        availableDrivers: availableByCategory[category]?.drivers || [] // Include driver details
      };
    });

    logger.info('Available drivers checked successfully', { distanceKm, categoryDetails, userId });
    return res.status(200).json({
      status: 'success',
      message: 'Available drivers and pricing details retrieved',
      data: { distanceKm, categoryDetails }
    });
  } catch (error) {
    logger.error('Error checking available drivers', { error: error.message, userId: req.user?._id });
    return res.status(500).json({ status: 'error', message: error.message || 'An unexpected error occurred' });
  }
};

module.exports = { checkAvailableDrivers };
