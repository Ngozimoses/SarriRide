const express = require('express');
const Trip = require('../models/Trip');
const Driver = require('../models/Driver');
const { validationResult } = require('express-validator');
const winston = require('winston');
const redis = require('../Config/redis'); // Redis client
const mongoose = require('mongoose');
const { getDistanceKm, calculatePrices } = require('../utils/rideUtils');
const admin = require('../Config/firebase'); // Import Firebase Admin SDK
const app = express();

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

const bookRide = async (req, res) => {
  const MAX_RETRIES = 3;
  let session;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    session = await mongoose.startSession({
      defaultTransactionOptions: {
        readConcern: { level: 'local' },
        writeConcern: { w: 'majority' },
        readPreference: 'primary'
      }
    });
    session.startTransaction({ maxCommitTimeMS: 10000 }); // 10-second timeout

    try {
      // Input validation
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        logger.warn('Validation failed for ride booking', { errors: errors.array(), userId: req.user?._id });
        return res.status(400).json({ status: 'error', message: 'Invalid request', errors: errors.array() });
      }

      const { currentLocationName, destinationName, currentLocation, destination, category } = req.body;
      const riderId = req.user?._id?.toString() || 'anonymous';

      // Validate inputs with detailed checks
      if (!currentLocation || !destination || !category ||
          typeof currentLocation.latitude !== 'number' ||
          typeof currentLocation.longitude !== 'number' ||
          typeof destination.latitude !== 'number' ||
          typeof destination.longitude !== 'number' ||
          typeof destinationName !== 'string' ||
          typeof currentLocationName !== 'string' ||
          !['luxury', 'comfort', 'xl'].includes(category)) {
        logger.warn('Invalid input types', { currentLocation, destination, category, userId: riderId });
        return res.status(400).json({ status: 'error', message: 'Valid coordinates, location names, and category are required' });
      }

      // Rate limiting
      const rateLimitKey = `rate_limit:book_ride:${riderId}`;
      const requests = await redis.incr(rateLimitKey);
      if (requests === 1) await redis.expire(rateLimitKey, 60); // 1-minute window
      if (requests > 10) {
        logger.warn('Rate limit exceeded for ride booking', { userId: riderId });
        return res.status(429).json({ status: 'error', message: 'Too many requests, please try again later' });
      }

      // Calculate distance and price
      const distanceKm = await getDistanceKm(currentLocation, destination, riderId);
      const price = await calculatePrices(distanceKm, category, riderId);

      // Find and lock an available driver
      const cacheKey = `drivers:near:${currentLocation.latitude}:${currentLocation.longitude}:${category}`;
      let availableDriver = await redis.get(cacheKey);

      if (!availableDriver) {
        const drivers = await Driver.aggregate([
          {
            $geoNear: {
              near: { type: 'Point', coordinates: [currentLocation.longitude, currentLocation.latitude] },
              distanceField: 'dist.calculated',
              maxDistance: 10000 * 1000, // 10km in meters
              query: { availabilityStatus: 'available', adminVerified: true },
              spherical: true
            }
          },
           {
          $group: {
            _id: '$category',
            drivers: { $push: { _id: '$_id', name: { $concat: ['$FirstName', ' ', '$LastName'] }, location: '$location' } },
            count: { $sum: 1 }
          }
        },
          { $limit: 1 } // Closest driver
        ]).session(session);

        availableDriver = drivers.length > 0 ? drivers[0] : null;
        if (availableDriver) {
          await redis.set(cacheKey, JSON.stringify(availableDriver), 'EX', 30); // Cache for 30 seconds
        }
      } else {
        availableDriver = JSON.parse(availableDriver);
      }
      if (!availableDriver || !availableDriver._id) {
        logger.warn('No available drivers', { currentLocation, destination, category, userId: riderId });
        return res.status(404).json({ status: 'error', message: 'No available drivers for the selected category' });
      }

      const driverId = availableDriver._id;

      // Lock driver with transaction to prevent race conditions
      const driver = await Driver.findOneAndUpdate(
        { _id: driverId, availabilityStatus: 'available' },
        { availabilityStatus: 'booked' },
        { new: true, session }
      );

      if (!driver) {
        logger.warn('Driver no longer available during booking', { driverId, userId: riderId });
        await redis.del(cacheKey); // Invalidate cache
        return res.status(400).json({ status: 'error', message: 'Selected driver is no longer available' });
      }

      // Create ride booking
      const trip = new Trip({
        clientId: riderId,
        driverId,
        category,
        requestedPickup: currentLocation,
        requestedDropoff: destination,
        distanceKm,
        price,
        seats: 1, // Default or from rider input
        status: 'pending'
      });

      await trip.save({ session });

      // Notify the driver via Socket.IO
      const io = req.app.get("io");
      io.to(driverId.toString()).emit('rideRequest', {
        rideId: trip._id,
        riderId,
        requestedPickup: currentLocation,
        requestedDropoff: destinationName,
        price,
        distanceKm
      });

      // Send FCM push notification to driver
      if (driver.fcmToken) {
        await admin.messaging().send({
          token: driver.fcmToken,
          notification: {
            title: 'New Ride Request',
            body: 'You have a new ride request waiting!'
          },
          data: {
            rideId: trip._id.toString(),
            riderId: riderId.toString(),
            requestedPickup: JSON.stringify(currentLocation),
            requestedDropoff: destinationName,
            price: price.toString(),
            distanceKm: distanceKm.toString()
          }
        });
        logger.info('FCM notification sent to driver', { driverId, rideId: trip._id });
      } else {
        logger.warn('No FCM token for driver', { driverId });
      }

      await session.commitTransaction();
      logger.info('Ride booked successfully', { rideId: trip._id, driverId, userId: riderId, attempt });
      return res.status(201).json({
        status: 'success',
        message: 'Ride booked, waiting for driver acceptance',
        data: { rideId: trip._id, price, distanceKm }
      });
    } catch (err) {
      await session.abortTransaction();
      if (err.name === 'MongoError' && err.code === 112) { // Deadlock error
        logger.warn('Deadlock detected, retrying...', { attempt, error: err.message, userId: riderId });
        if (attempt < MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt - 1))); // Exponential backoff
          continue;
        }
      }
      throw err; 
    } finally {
      session.endSession();
    }
  }

  logger.error('Max retries exceeded for ride booking', { userId: req.user?._id });
  return res.status(503).json({ status: 'error', message: 'Service temporarily unavailable, please try again later' });
};

module.exports = { bookRide };
