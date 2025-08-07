const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { body, check } = require('express-validator');
import axios from 'axios';
const router = express.Router();
const calculatePriceLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { status: 'error', message: 'Too many requests, please try again later' },
});
const {authMiddleware} = require('../middlewares/auth.js');

const { calculateRidePrice, endTrip } = require('../Controllers/Client.controller.js');

// router.post(
//   '/calculate-price',
//   calculatePriceLimiter,
//   [
//     check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
//     check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required'),
//     check('destination.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid destination latitude (-90 to 90) required'),
//     check('destination.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid destination longitude (-180 to 180) required'),
//   ],
//   calculateRidePrice
// );
// module.exports = router;




// const express = require('express');
// const { check } = require('express-validator');
// const { calculateRidePrice, endTrip } = require('../Controllers/Client.controller');
// const rateLimit = require('express-rate-limit');
// const router = express.Router();

// const calculatePriceLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100,
//   message: { status: 'error', message: 'Too many requests, please try again later' }
// });

router.post(
  '/calculate-price',
  authMiddleware('client'),
  calculatePriceLimiter,
  [
    check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
    check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required'),
    check('destination.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid destination latitude (-90 to 90) required'),
    check('destination.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid destination longitude (-180 to 180) required')
  ],
  calculateRidePrice
);

router.post(
  '/end-trip',
  authMiddleware('client'),
  calculatePriceLimiter,
  [
    check('userId').isMongoId().withMessage('Valid user ID required'),
    check('category').isIn(['luxury', 'comfort', 'xl']).withMessage('Valid category (luxury, comfort, xl) required'),
    check('startLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid start latitude (-90 to 90) required'),
    check('startLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid start longitude (-180 to 180) required'),
    check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
    check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required')
  ],
  endTrip
);

module.exports = router;
