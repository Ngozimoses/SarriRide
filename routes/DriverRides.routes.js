const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { body, check } = require('express-validator');
const router = express.Router();
const Limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { status: 'error', message: 'Too many requests, please try again later' },
});
const {authMiddleware} = require('../middlewares/auth.js');
const { updateDriverLocation } = require('../Controllers/UpdateLocation.controller');

router.put(
  '/update-location',
  authMiddleware('driver'),
  Limiter,
  [
    check('latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid latitude (-90 to 90) required'),
    check('longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid longitude (-180 to 180) required'),
    check('availabilityStatus')
      .optional()
      .isIn(['available', 'unavailable', 'on_trip'])
      .withMessage('Invalid availability status')
  ],
  updateDriverLocation
);
module.exports = router;
