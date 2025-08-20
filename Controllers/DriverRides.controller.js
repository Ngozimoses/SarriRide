const { validationResult } = require('express-validator');
const axios = require('axios');
const redis = require('../Config/redis');
const Driver = require('../models/Driver')
const Pricing = require ('../models/PricingSchema.js')

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

const availableDriver = async (req,res)=>{
  try{
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

        // checking if the Users Location Matches the driver Location 
        //POST https://sarriride.onrender.com/clientRide/calculate-price?currentLat=51.5074&currentLng=-0.1278&destLat=48.8566&destLng=2.3522

         const clientUrl = `https://sarriride.onrender.com/clientRide/calculate-price?currentLat=${currentLocation.latitude}&currentLng=${currentLocation.longitude}&destLat=${destination.latitude}&destLng=${destination.longitude}`
          const resFromClientUrl = axios.post(clientUrl,
            {},
            {
              headers: { Authorization: `Bearer ${req.headers.authorization?.split(" ")[1]}` }
            }
          )
        const driverCategory = await Driver.findOne({ category });
        const bookingDetails = {}
        // Fetch pricing from MongoDB
        const pricing = await Pricing.find({ category: driverCategory?.category });
        pricing.forEach(({ category, baseFee, perKm, minimumFare, seats }) => {
          const price = Math.max(baseFee + perKm * distanceKm, minimumFare);
          bookingDetails[category] = {
            price: Math.round(price * 100) / 100,
            seats
          };
        });
        if (pricing.length === 0) {
          logger.error('No pricing data found in database');
          return res.status(500).json({ status: 'error', message: 'Pricing data not configured' });
        }
        res.json({
          status:"success",
          data:{
            resFromClientUrl,
            bookingDetails
          }
        })
        // res.json({ status: 'success', data: drivers });

  }catch(err){
  logger.error(`Error occurred while fetching available drivers: ${err.message}`);
  res.status(500).json({ error: 'Internal Server Error' }); 
}
}

module.exports= {availableDriver}
