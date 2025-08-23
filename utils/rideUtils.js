
const axios = require('axios');
const redis = require('../Config/redis');
const Pricing = require('../models/PricingSchema');
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

const DISTANCE_CACHE_TTL_SECONDS = 3600; // 1 hour

/**
 * Calculates the distance in kilometers between two coordinates using Google Maps API or cache.
 * @param {Object} currentLocation - { latitude, longitude }
 * @param {Object} destination - { latitude, longitude }
 * @param {string} userId - For logging
 * @returns {Promise<number>} Distance in km
 */

async function getDistanceKm(currentLocation, destination, userId) {
  // Validate input parameters
  if (!currentLocation?.latitude || !currentLocation?.longitude || !destination?.latitude || !destination?.longitude) {
    const errorMsg = 'Invalid location data: missing latitude or longitude';
    logger.error('Input validation failed', { userId, currentLocation, destination, error: errorMsg });
    throw new Error(`[InputValidation] ${errorMsg}`);
  }

  const origin = `${currentLocation.latitude},${currentLocation.longitude}`;
  const dest = `${destination.latitude},${destination.longitude}`;
  const cacheKey = `distance:${origin}:${dest}`;

  let distanceKm;
  try {
    const cachedDistance = await redis.get(cacheKey);
    if (cachedDistance) {
      distanceKm = parseFloat(cachedDistance);
      logger.info('Distance retrieved from cache', { cacheKey, distanceKm, userId });
    } else {
      const apiKey = process.env.GOOGLE_MAPS_API_KEY;
      if (!apiKey) {
        const errorMsg = 'Missing GOOGLE_MAPS_API_KEY environment variable';
        logger.error('Configuration error', { userId, error: errorMsg });
        throw new Error(`[Configuration] ${errorMsg}`);
      }

      const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${origin}&destinations=${dest}&key=${apiKey}`;
      logger.debug('Calling Google Maps API', { url, userId });

      const response = await axios.get(url);
      logger.debug('Google Maps API response received', { status: response.status, userId });

      const distanceMeters = response.data.rows[0]?.elements[0]?.distance?.value;
      if (!distanceMeters) {
        logger.warn('No distance data from Google Maps API', { 
          origin, 
          dest, 
          userId, 
          apiResponse: response.data 
        });
        throw new Error(`[APIResponse] Failed to get distance from Google Maps: ${JSON.stringify(response.data)}`);
      }

      distanceKm = distanceMeters / 1000;
      await redis.set(cacheKey, distanceKm.toString(), 'EX', DISTANCE_CACHE_TTL_SECONDS);
      logger.info('Distance calculated and cached', { cacheKey, distanceKm, userId });
    }
  } catch (error) {
    let errorPrefix = '[UnknownError]';
    let detailedMessage = 'An unexpected error occurred';

    if (error.response) {
      // API returned an error (e.g., 400, 403)
      errorPrefix = '[APIError]';
      detailedMessage = `Google Maps API error: ${error.response.data.error_message || 'Unknown API error'}`;
      logger.error(detailedMessage, { 
        userId, 
        status: error.response.status, 
        data: error.response.data, 
        origin, 
        dest 
      });
    } else if (error.request) {
      // No response received (network issue)
      errorPrefix = '[NetworkError]';
      detailedMessage = 'Failed to connect to Google Maps API';
      logger.error(detailedMessage, { userId, error: error.message, origin, dest });
    } else if (error.message.startsWith('[InputValidation]') || error.message.startsWith('[Configuration]') || error.message.startsWith('[APIResponse]')) {
      // Predefined errors from input validation or API response
      errorPrefix = error.message.split(']')[0] + ']';
      detailedMessage = error.message.split(']').slice(1).join(']').trim();
    } else {
      // Other unexpected errors
      logger.error('Unexpected error', { userId, error: error.message, stack: error.stack, origin, dest });
    }

    throw new Error(`${errorPrefix} ${detailedMessage}`);
  }

  return distanceKm;
}
// async function getDistanceKm(currentLocation, destination, userId) {
//   const origin = `${currentLocation.latitude},${currentLocation.longitude}`;
//   const dest = `${destination.latitude},${destination.longitude}`;
//   const cacheKey = `distance:${origin}:${dest}`;

//   let distanceKm;
//   const cachedDistance = await redis.get(cacheKey);
//   if (cachedDistance) {
//     distanceKm = parseFloat(cachedDistance);
//     logger.info('Distance retrieved from cache', { cacheKey, distanceKm, userId });
//   } else {
//     const apiKey = process.env.GOOGLE_MAPS_API_KEY;
//     const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${origin}&destinations=${dest}&key=${apiKey}`;
//     const response = await axios.get(url);
//     const distanceMeters = response.data.rows[0].elements[0].distance?.value;
//     if (!distanceMeters) {
//       logger.warn('Failed to get distance from Google Maps', { origin, dest, userId });
//       throw new Error('Failed to calculate distance');
//     }
//     distanceKm = distanceMeters / 1000;
//     await redis.set(cacheKey, distanceKm.toString(), 'EX', DISTANCE_CACHE_TTL_SECONDS);
//     logger.info('Distance calculated and cached', { cacheKey, distanceKm, userId });
//   }
//   return distanceKm;
// }

/**
 * Calculates prices for all pricing categories based on distance.
 * @param {number} distanceKm
 * @param {string} userId - For logging
 * @returns {Promise<Object>} Prices object with category as key
 */
async function calculatePrices(distanceKm, userId) {
  const pricing = await Pricing.find({}).lean(); // Lean was used for faster queries
  if (pricing.length === 0) {
    logger.error('No pricing data found in database', { userId });
    throw new Error('Pricing data not configured');
  }
  const prices = {};
  pricing.forEach(({ category, baseFee, perKm, minimumFare, seats }) => {
    const price = Math.max(baseFee + perKm * distanceKm, minimumFare);
    prices[category] = {
      price: Math.round(price * 100) / 100,
      seats
    };
  });
  return prices;
}

module.exports = { getDistanceKm, calculatePrices };
