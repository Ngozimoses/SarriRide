
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
  const origin = `${currentLocation.latitude},${currentLocation.longitude}`;
  const dest = `${destination.latitude},${destination.longitude}`;
  const cacheKey = `distance:${origin}:${dest}`;

  let distanceKm;
  const cachedDistance = await redis.get(cacheKey);
  if (cachedDistance) {
    distanceKm = parseFloat(cachedDistance);
    logger.info('Distance retrieved from cache', { cacheKey, distanceKm, userId });
  } else {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${origin}&destinations=${dest}&key=${apiKey}`;
    const response = await axios.get(url);
    const distanceMeters = response.data.rows[0].elements[0].distance?.value;
    if (!distanceMeters) {
      logger.warn('Failed to get distance from Google Maps', { origin, dest, userId });
      throw new Error('Failed to calculate distance');
    }
    distanceKm = distanceMeters / 1000;
    await redis.set(cacheKey, distanceKm.toString(), 'EX', DISTANCE_CACHE_TTL_SECONDS);
    logger.info('Distance calculated and cached', { cacheKey, distanceKm, userId });
  }
  return distanceKm;
}

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
