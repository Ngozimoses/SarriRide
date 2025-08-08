const express = require('express');
const passport = require('passport'); // Assuming you use passport-google-oauth20
const router = express.Router();
const {
  registrationValidation,
  loginValidation,
  refreshTokenValidation,
} = require('../middlewares/Validation');
const{ VerifyOtp,UpdatePassword,ForgotPassword} = require('../middlewares/auth');
const {
  ClientRegistration,
  ClientLogin,
  ClientRefreshToken,
  ClientLogout,
  ClientFacebookDataDeletion
} = require('../Controllers/client.auth.controller');

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: Google OAuth 2.0 authentication for clients
 */

/**
 * @swagger
 * /auth/client/google:
 *   get:
 *     summary: Initiate Google login
 *     tags: [Authentication]
 *     description: >
 *       Opens Google's OAuth 2.0 login page.  
 *       After a successful login, Google redirects the user to `/auth/client/google/callback`
 *       with authentication details.
 *     responses:
 *       302:
 *         description: Redirect to Google login page.
 *         headers:
 *           Location:
 *             description: Google OAuth 2.0 login URL
 *             schema:
 *               type: string
 */
router.get('/auth/client/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

/**
 * @swagger
 * /auth/client/google/callback:
 *   get:
 *     summary: Google login callback
 *     tags: [Authentication]
 *     description: >
 *       This endpoint is automatically called by Google after successful login.  
 *       The response contains client info, an access token, and a refresh token.
 *     parameters:
 *       - in: query
 *         name: code
 *         schema:
 *           type: string
 *         description: Google authorization code (automatically provided after login).
 *     responses:
 *       200:
 *         description: Google login successful
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Google login successful
 *               data:
 *                 client:
 *                   name: Eli
 *                   _id: 6891f47102d7b380d09d
 *                   email: eli@gmail.com
 *                   role: client
 *                   isVerified: true
 *                 accessToken: a6bf0206e506ad5820c687a1529b627a:...
 *                 refreshToken: b16439fdf624657182947666e999e22e:...
 */
router.get('/auth/client/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.json({
      status: 'success',
      message: 'Google login successful',
      data: {
        client: {
          name: req.user.name,
          _id: req.user._id,
          email: req.user.email,
          role: req.user.role,
          isVerified: req.user.isVerified
        },
        accessToken: req.user.accessToken,
        refreshToken: req.user.refreshToken
      }
    });
  }
);

/**
 * @swagger
 * /auth/client/register:
 *   post:
 *     summary: Register a new client
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - FirstName
 *               - LastName
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 example: eli99@gmail.com
 *               FirstName:
 *                 type: string
 *                 example: John
 *               LastName:
 *                 type: string
 *                 example: Doe
 *               password:
 *                 type: string
 *                 example: securePass123
 *     responses:
 *       200:
 *         description: Registration successful Otp sent
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Registration successful, OTP sent
 *               data:
 *                 client:
 *                   _id: 6895e7cf8773671f9cdb8e08
 *                   email: elijahog99@gmail.com
 *                   role: client
 *                   isVerified: false
 */

router.post('/client/register', registrationValidation, ClientRegistration);
/**
 * @swagger
 * /auth/client/verify-otp:
 *   post:
 *     summary: Verify client OTP
 *     tags: [Authentication]
 *     description: >
 *       Verifies the One-Time Password (OTP) for a client account.  
 *       This endpoint checks the provided OTP against the one sent to the client's email or phone.  
 *       A successful verification marks the client as verified.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: elijahog99@gmail.com
 *               otp:
 *                 type: string
 *                 example: "509526"
 *               role:
 *                 type: string
 *                 example: client
 *             required:
 *               - email
 *               - otp
 *               - role
 *     responses:
 *       200:
 *         description: Verification successful
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Verification successful
 *               data:
 *                 user:
 *                   _id: 6895f83ce8fd2cab75782eb9
 *                   email: elijahog99@gmail.com
 *                   role: client
 *                   isVerified: true
 *       400:
 *         description: Invalid or expired OTP
 *       500:
 *         description: Server error
 */

router.post('/client/verify-otp', VerifyOtp);


module.exports = router;
