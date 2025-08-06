const { check, validationResult } = require('express-validator');
const Pricing = require('../models/PricingSchema');
const { calculateDistance } = require('../utils/distanceCalculator');
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
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation failed for ride price calculation', { errors: errors.array() });
      return res.status(400).json({ status: 'error', message: 'Invalid request', data: { errors: errors.array() } });
    }

    const { currentLocation, destination } = req.body;

    // Validate coordinates
    if (!currentLocation || !destination || 
        typeof currentLocation.latitude !== 'number' || 
        typeof currentLocation.longitude !== 'number' || 
        typeof destination.latitude !== 'number' || 
        typeof destination.longitude !== 'number' ||
        Math.abs(currentLocation.latitude) > 90 || 
        Math.abs(currentLocation.longitude) > 180 ||
        Math.abs(destination.latitude) > 90 || 
        Math.abs(destination.longitude) > 180) {
      logger.warn('Invalid coordinates provided', { currentLocation, destination });
      return res.status(400).json({ status: 'error', message: 'Valid latitude (-90 to 90) and longitude (-180 to 180) required' });
    }

    // Calculate distance (Haversine formula)
    const distanceKm = calculateDistance(
      currentLocation.latitude,
      currentLocation.longitude,
      destination.latitude,
      destination.longitude
    );

    // Optional: Google Maps Distance Matrix API
    /*
    const axios = require('axios');
    const origin = `${currentLocation.latitude},${currentLocation.longitude}`;
    const dest = `${destination.latitude},${destination.longitude}`;
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${origin}&destinations=${dest}&key=${apiKey}`;
    const response = await axios.get(url);
    const distanceMeters = response.data.rows[0].elements[0].distance.value;
    const distanceKm = distanceMeters / 1000;
    if (!distanceKm) {
      logger.warn('Failed to get distance from Google Maps', { origin, dest });
      return res.status(500).json({ status: 'error', message: 'Failed to calculate distance' });
    }
    */
    // Fetch pricing from MongoDB
    const pricing = await Pricing.find({});
    if (pricing.length === 0) {
      logger.error('No pricing data found in database');
      return res.status(500).json({ status: 'error', message: 'Pricing data not configured' });
    }
    // Calculate prices for all categories
    const prices = {};
    pricing.forEach(({ category, baseFee, perKm, minimumFare }) => {
      const price = Math.max(baseFee + perKm * distanceKm, minimumFare);
      prices[category] = Math.round(price * 100) / 100; // Round to 2 decimals
    });

    logger.info('Ride price calculated', { distanceKm, prices });
    return res.status(200).json({
      status: 'success',
      message: 'Ride prices calculated',
      data: { distanceKm, prices },
    });
  } catch (error) {
    logger.error('Ride price calculation error', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
  }
};

module.exports = { calculateRidePrice };
