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
const {availableDriver} = require('../Controllers/DriverRides.controller.js');

router.post('/client/checkingAvailableDrivers',authMiddleware("client"),
[
    check('currentLocation.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid current latitude (-90 to 90) required'),
    check('currentLocation.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid current longitude (-180 to 180) required'),
    check('destination.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid destination latitude (-90 to 90) required'),
    check('destination.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid destination longitude (-180 to 180) required')
  ],
  availableDriver
);

