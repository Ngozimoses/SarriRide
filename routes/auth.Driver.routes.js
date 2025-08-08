const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { body, check } = require('express-validator');
const router = express.Router();
const {verifyEmail, verifyDriverOtp, registerDriver, uploadImages} = require('../Controllers/Driver.controller.js');

router.post('/driver/verifyDriverEmail', [
  check('email').isEmail().withMessage('Valid email is required'),
], verifyEmail);

router.post('/driver/verifyDriverOtp', [
  check('email').isEmail().withMessage('Valid email is required'),
  check('otp').isNumeric().withMessage('Valid OTP is required'),
], verifyDriverOtp);

router.post('/driver/register', [
  check('email').isEmail().withMessage('Valid email is required'),
  check('FirstName').notEmpty().withMessage('First name is required'),
  check('LastName').notEmpty().withMessage('Last name is required'),
  check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  check('phoneNumber').notEmpty().withMessage('Phone number is required'),
  check('DateOfBirth').notEmpty().withMessage('Date of birth is required'),
  check('Gender').notEmpty().withMessage('Gender is required'),
  check('licenseNumber').notEmpty().withMessage('License number is required'),
  check('drivingLicense.issueDate').notEmpty().withMessage('License issue date is required'),
  check('drivingLicense.expiryDate').notEmpty().withMessage('License expiry date is required'),
  check('currentAddress.address').notEmpty().withMessage('Current address is required'),
  check('currentAddress.state').notEmpty().withMessage('Current state is required'),
  check('currentAddress.city').notEmpty().withMessage('Current city is required'),
  check('currentAddress.country').notEmpty().withMessage('Current country is required'),
  check('currentAddress.postalCode').notEmpty().withMessage('Current postal code is required'),
  check('permanentAddress.address').notEmpty().withMessage('Permanent address is required'),
  check('permanentAddress.state').notEmpty().withMessage('Permanent state is required'),
  check('permanentAddress.city').notEmpty().withMessage('Permanent city is required'),
  check('permanentAddress.country').notEmpty().withMessage('Permanent country is required'),
  check('permanentAddress.postalCode').notEmpty().withMessage('Permanent postal code is required'),
  check('emergencyContactNumber').notEmpty().withMessage('Emergency contact number is required'),
  check('bankDetails.bankAccountNumber').notEmpty().withMessage('Bank account number is required'),
  check('bankDetails.bankName').notEmpty().withMessage('Bank name is required'),
  check('bankDetails.bankAccountName').notEmpty().withMessage('Bank account name is required'),
  check('vehicleDetails.make').notEmpty().withMessage('Vehicle make is required'),
  check('vehicleDetails.model').notEmpty().withMessage('Vehicle model is required'),
  check('vehicleDetails.year').isNumeric().withMessage('Vehicle year must be a number'),
  check('vehicleDetails.licensePlate').notEmpty().withMessage('Vehicle license plate is required')
], registerDriver, uploadImages);
router.post('/driver/upload-images', [
], uploadImages);


module.exports = router;
