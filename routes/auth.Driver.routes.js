const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { body, check } = require('express-validator');
const router = express.Router();
const {verifyEmail, verifyDriverOtp} = require('../Controllers/Driver.controller.js');

router.post('/driver/verifyDriverEmail', [
  check('email').isEmail().withMessage('Valid email is required'),
], verifyEmail);

router.post('/driver/verifyDriverOtp', [
  check('email').isEmail().withMessage('Valid email is required'),
  check('otp').isNumeric().withMessage('Valid OTP is required'),
], verifyDriverOtp);



