const express = require('express');
const passport = require('passport'); // Assuming you use passport-google-oauth20
const router = express.Router();

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

module.exports = router;
