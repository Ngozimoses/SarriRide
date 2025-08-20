const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { check } = require('express-validator');
const router = express.Router();
const { authMiddleware } = require('../middlewares/auth');
const { calculateRidePrice, mapQueryToBody } = require('../Controllers/Client.controller');
const { checkAvailableDrivers } = require('../Controllers/DriverRides.controller');


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

// Endpoint 3: Update Driver Location


module.exports = router;



// const express = require('express');
// const { rateLimit } = require('express-rate-limit');
// const { body, check } = require('express-validator');
// const router = express.Router();
// const Limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100,
//   message: { status: 'error', message: 'Too many requests, please try again later' },
// });
// const {authMiddleware} = require('../middlewares/auth.js');

// const { calculateRidePrice, endTrip, mapQueryToBody} = require('../Controllers/Client.controller.js');
// const {availableDriver} = require('../Controllers/DriverRides.controller.js');

// router.post(
//   '/calculate-price',
//   authMiddleware('client'),
//   mapQueryToBody,
//   Limiter,
//   [
//     check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
//     check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required'),
//     check('destination.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid destination latitude (-90 to 90) required'),
//     check('destination.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid destination longitude (-180 to 180) required')
//   ],
//   calculateRidePrice
// );


// router.post('/checkingAvailableDrivers', authMiddleware("client"),
//   Limiter,
//   [
//     check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
//     check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required'),
//     check('destination.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid destination latitude (-90 to 90) required'),
//     check('destination.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid destination longitude (-180 to 180) required')
//   ],
//   availableDriver
// );

// router.post(
//   '/end-trip',
//   authMiddleware('client'),
//   Limiter,
//   [
//     check('userId').isMongoId().withMessage('Valid user ID required'),
//     check('category').isIn(['luxury', 'comfort', 'xl']).withMessage('Valid category (luxury, comfort, xl) required'),
//     check('startLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid start latitude (-90 to 90) required'),
//     check('startLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid start longitude (-180 to 180) required'),
//     check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
//     check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required')
//   ],
//   endTrip
// );

// module.exports = router;
