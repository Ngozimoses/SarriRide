const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { body } = require('express-validator');

const {
  ClientRegistration,
  ClientLogin,
  ClientRefreshToken,
  ClientLogout,
  ClientFacebookDataDeletion
} = require('../Controllers/client.auth.controller');
const {
  DriverRegistration,
  DriverLogin,
  DriverRefreshToken,
  DriverLogout,
} = require('../Controllers/Driver.controller.js');
const {
  AdminLogin,
  AdminRefreshToken,
  AdminLogout,
} = require('../Controllers/admin.auth.controller');
const {
  registrationValidation,
  loginValidation,
  refreshTokenValidation,
} = require('../middlewares/Validation');
const {authMiddleware} = require('../middlewares/auth.js');
const{ VerifyOtp} = require('../middlewares/auth');
const { ClientGoogleAuth, ClientGoogleCallback, ClientFacebookAuth, ClientFacebookCallback } = require('../Controllers/client.auth.controller')


const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { status: 'error', message: 'Too many login attempts, please try again later' },
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { status: 'error', message: 'Too many refresh attempts, please try again later' },
});

router.get('/client/google', loginLimiter, ClientGoogleAuth);
router.get('/client/google/callback', loginLimiter, ClientGoogleCallback);
router.get('/client/facebook', loginLimiter, ClientFacebookAuth);
router.get('/client/facebook/callback', loginLimiter, ClientFacebookCallback);
router.post('/client/facebook/data-deletion-status',[body('confirmation_code').notEmpty().withMessage('Confirmation code is required')], ClientFacebookDataDeletion);


router.post('/client/register', registrationValidation, ClientRegistration);
router.post('/client/login', loginLimiter, loginValidation, ClientLogin, authMiddleware('client'));
router.post('/client/refresh-token', refreshLimiter, refreshTokenValidation, ClientRefreshToken);
router.post('/client/logout', refreshTokenValidation, ClientLogout, authMiddleware('client'));
router.post('/client/verify-otp', VerifyOtp);

router.post('/driver/register', registrationValidation, DriverRegistration);
router.post('/driver/login', loginLimiter, loginValidation, DriverLogin, authMiddleware('driver'));
router.post('/driver/refresh-token', refreshLimiter, refreshTokenValidation, DriverRefreshToken);
router.post('/driver/logout', refreshTokenValidation, DriverLogout, authMiddleware('driver'));

router.post('/admin/login', loginLimiter, loginValidation, AdminLogin, authMiddleware('admin'));
router.post('/admin/refresh-token', refreshLimiter, refreshTokenValidation, AdminRefreshToken, authMiddleware('admin'));
router.post('/admin/logout', refreshTokenValidation, AdminLogout, authMiddleware('admin'));

// Example protected routes
router.get('/client/profile', authMiddleware('client'), (req, res) => {
  res.json({ status: 'success', message: 'Client profile', user: req.user });
});
router.get('/driver/dashboard', authMiddleware('driver'), (req, res) => {
  res.json({ status: 'success', message: 'Driver dashboard', user: req.user });
});
router.get('/admin/panel', authMiddleware('admin'), (req, res) => {
  res.json({ status: 'success', message: 'Admin panel', user: req.user });
});

module.exports = router;
