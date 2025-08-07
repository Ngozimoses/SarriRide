const { validationResult } = require('express-validator');
const Pricing = require('../models/PricingSchema');
const { calculateDistance } = require('../utils/distanceCalculator');
const redis = require('../Config/redis');
const Trip = require('../models/Trip');
const axios = require('axios');


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

// const calculateRidePrice = async (req, res) => {
//   try {
//     // Validate input
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       logger.warn('Validation failed for ride price calculation', { errors: errors.array() });
//       return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
//     }

//     const { currentLocation, destination } = req.body;

//     // Validate coordinates
//     if (!currentLocation || !destination || 
//         typeof currentLocation.latitude !== 'number' || 
//         typeof currentLocation.longitude !== 'number' || 
//         typeof destination.latitude !== 'number' || 
//         typeof destination.longitude !== 'number' ||
//         Math.abs(currentLocation.latitude) > 90 || 
//         Math.abs(currentLocation.longitude) > 180 ||
//         Math.abs(destination.latitude) > 90 || 
//         Math.abs(destination.longitude) > 180) {
//       logger.warn('Invalid coordinates provided', { currentLocation, destination });
//       return res.status(400).json({ status: 'error', message: 'Valid latitude (-90 to 90) and longitude (-180 to 180) required' });
//     }

//     // Calculate distance (Haversine formula)
//     const distanceKm = calculateDistance(
//       currentLocation.latitude,
//       currentLocation.longitude,
//       destination.latitude,
//       destination.longitude
//     );

//     // Optional: Google Maps Distance Matrix API
//     /*
//     const axios = require('axios');
//     const origin = `${currentLocation.latitude},${currentLocation.longitude}`;
//     const dest = `${destination.latitude},${destination.longitude}`;
//     const apiKey = process.env.GOOGLE_MAPS_API_KEY;
//     const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${origin}&destinations=${dest}&key=${apiKey}`;
//     const response = await axios.get(url);
//     const distanceMeters = response.data.rows[0].elements[0].distance.value;
//     const distanceKm = distanceMeters / 1000;
//     if (!distanceKm) {
//       logger.warn('Failed to get distance from Google Maps', { origin, dest });
//       return res.status(500).json({ status: 'error', message: 'Failed to calculate distance' });
//     }
//     */

//     // Fetch pricing from MongoDB
//     const pricing = await Pricing.find({});
//     if (pricing.length === 0) {
//       logger.error('No pricing data found in database');
//       return res.status(500).json({ status: 'error', message: 'Pricing data not configured' });
//     }

//     // Calculate prices for all categories, including seats
//     const prices = {};
//     pricing.forEach(({ category, baseFee, perKm, minimumFare, seats }) => {
//       const price = Math.max(baseFee + perKm * distanceKm, minimumFare);
//       prices[category] = {
//         price: Math.round(price * 100) / 100,
//         seats: seats
//       };
//     });

//     logger.info('Ride price calculated', { distanceKm, prices });
//     return res.status(200).json({
//       status: 'success',
//       message: 'Ride prices calculated',
//       data: { distanceKm, prices },
//     });
//   } catch (error) {
//     logger.error('Ride price calculation error', { error: error.message });
//     return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
//   }
// };

// module.exports = { calculateRidePrice };




// const { check, validationResult } = require('express-validator');
// const axios = require('axios');
// const Pricing = require('../models/Pricing');
// const Trip = require('../models/Trip');
// const winston = require('winston');
// const redis = require('../Config/redis');

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

const calculateRidePrice = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for ride price calculation', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { currentLocation, destination } = req.body;

    if (!currentLocation || !destination || 
        typeof currentLocation.latitude !== 'number' || 
        typeof currentLocation.longitude !== 'number' || 
        typeof destination.latitude !== 'number' || 
        typeof destination.longitude !== 'number') {
      logger.warn('Invalid coordinates provided', { currentLocation, destination });
      return res.status(400).json({ status: 'error', message: 'Valid latitude and longitude required' });
    }

    // Calculate distance using Google Maps Distance Matrix API
    const origin = `${currentLocation.latitude},${currentLocation.longitude}`;
    const dest = `${destination.latitude},${destination.longitude}`;
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    const cacheKey = `distance:${origin}:${dest}`;
    let distanceKm;

    const cachedDistance = await redis.get(cacheKey);
    if (cachedDistance) {
      distanceKm = parseFloat(cachedDistance);
    } else {
      const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${origin}&destinations=${dest}&key=${apiKey}`;
      const response = await axios.get(url);
      const distanceMeters = response.data.rows[0].elements[0].distance?.value;
      if (!distanceMeters) {
        logger.warn('Failed to get distance from Google Maps', { origin, dest });
        return res.status(500).json({ status: 'error', message: 'Failed to calculate distance' });
      }
      distanceKm = distanceMeters / 1000;
    await redis.set(cacheKey, distanceKm.toString(), 'EX', 3600);
    }

    // Fetch pricing from MongoDB
    const pricing = await Pricing.find({});
    if (pricing.length === 0) {
      logger.error('No pricing data found in database');
      return res.status(500).json({ status: 'error', message: 'Pricing data not configured' });
    }

    // Calculate prices for all categories
    const prices = {};
    pricing.forEach(({ category, baseFee, perKm, minimumFare, seats }) => {
      const price = Math.max(baseFee + perKm * distanceKm, minimumFare);
      prices[category] = {
        price: Math.round(price * 100) / 100,
        seats
      };
    });

    logger.info('Ride price calculated', { distanceKm, prices, userId: req.user?._id });
    return res.status(200).json({
      status: 'success',
      message: 'Ride prices calculated',
      data: { distanceKm, prices }
    });
  } catch (error) {
    logger.error('Ride price calculation error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

const endTrip = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for trip end', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { userId, category, startLocation, currentLocation } = req.body;

    if (!userId || !category || !startLocation || !currentLocation || 
        typeof startLocation.latitude !== 'number' || 
        typeof startLocation.longitude !== 'number' || 
        typeof currentLocation.latitude !== 'number' || 
        typeof currentLocation.longitude !== 'number') {
      logger.warn('Invalid data provided for trip end', { userId, category, startLocation, currentLocation });
      return res.status(400).json({ status: 'error', message: 'Valid user ID, category, start and current location coordinates required' });
    }

    // Verify userId matches authenticated user
    if (userId !== req.user._id.toString()) {
      logger.warn('User ID mismatch', { providedUserId: userId, authenticatedUserId: req.user._id });
      return res.status(403).json({ status: 'error', message: 'Forbidden - User ID mismatch' });
    }

    // Calculate distance using Google Maps Distance Matrix API
    const origin = `${startLocation.latitude},${startLocation.longitude}`;
    const dest = `${currentLocation.latitude},${currentLocation.longitude}`;
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    const cacheKey = `distance:${origin}:${dest}`;
    let distanceKm;

    const cachedDistance = await redis.get(cacheKey);
    if (cachedDistance) {
      distanceKm = parseFloat(cachedDistance);
    } else {
      const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${origin}&destinations=${dest}&key=${apiKey}`;
      const response = await axios.get(url);
      const distanceMeters = response.data.rows[0].elements[0].distance?.value;
      if (!distanceMeters) {
        logger.warn('Failed to get distance from Google Maps', { origin, dest });
        return res.status(500).json({ status: 'error', message: 'Failed to calculate distance' });
      }
      distanceKm = distanceMeters / 1000;
      await redis.setEx(cacheKey, 3600, distanceKm.toString()); // Cache for 1 hour
    }

    // Fetch pricing for the selected category
    const pricing = await Pricing.findOne({ category });
    if (!pricing) {
      logger.error('Pricing not found for category', { category });
      return res.status(400).json({ status: 'error', message: `Invalid category: ${category}` });
    }

    const { baseFee, perKm, minimumFare, seats } = pricing;
    const price = Math.max(baseFee + perKm * distanceKm, minimumFare);

    // Save trip to MongoDB
    const trip = new Trip({
      userId,
      category,
      startLocation,
      endLocation: currentLocation,
      distanceKm,
      price: Math.round(price * 100) / 100,
      seats
    });
    await trip.save();

    logger.info('Trip ended and recorded', { tripId: trip._id, distanceKm, price, userId });
    return res.status(200).json({
      status: 'success',
      message: 'Trip ended',
      data: {
        tripId: trip._id,
        distanceKm,
        price: Math.round(price * 100) / 100,
        seats,
        startLocation,
        endLocation: currentLocation
      }
    });
  } catch (error) {
    logger.error('Trip end error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

module.exports = { calculateRidePrice, endTrip };
