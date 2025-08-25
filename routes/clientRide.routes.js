const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { check } = require('express-validator');
const router = express.Router();
const { authMiddleware } = require('../middlewares/auth');
const { calculateRidePrice, mapQueryToBody } = require('../Controllers/Client.controller');
const { checkAvailableDrivers } = require('../Controllers/DriverRides.controller');
const {bookRide} = require('../Controllers/Booking.controller')


const Limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { status: 'error', message: 'Too many requests, please try again later' }
});

// Endpoint 1: Calculate Ride Price
router.post(
  '/calculate-price',
  authMiddleware('client'),
  mapQueryToBody,
  Limiter,
  [
    check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
    check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required'),
    check('destination.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid destination latitude (-90 to 90) required'),
    check('destination.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid destination longitude (-180 to 180) required')
  ],
  calculateRidePrice
);

// Endpoint 2: Check Available Drivers
router.post(
  '/checkingAvailableDrivers',
  authMiddleware('client'),
  Limiter,
  [
    check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
    check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required'),
    check('destination.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid destination latitude (-90 to 90) required'),
    check('destination.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid destination longitude (-180 to 180) required')
  ],
  checkAvailableDrivers
);
router.post('/bookRide', authMiddleware('client'), Limiter, bookRide);

module.exports = router;



