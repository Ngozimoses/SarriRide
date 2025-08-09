const express = require('express');
const passport = require('passport');
const { rateLimit } = require('express-rate-limit');
const { body, check } = require('express-validator');
const {authMiddleware} = require('../middlewares/auth.js');
const {DriverLogin} = require('../Controllers/Driver.controller.js');
const router = express.Router();
const {
  registrationValidation,
  loginValidation,
  refreshTokenValidation,
} = require('../middlewares/Validation');
const{ VerifyOtp,UpdatePassword,ForgotPassword} = require('../middlewares/auth');
const {authMiddleware} = require('../middlewares/auth.js');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { status: 'error', message: 'Too many login attempts, please try again later' },
});

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
 *                   email: eli@gmail.com
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
 *                 example: eli@gmail.com
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
 *                   email: el@gmail.com
 *                   role: client
 *                   isVerified: true
 *       400:
 *         description: Invalid or expired OTP
 *       500:
 *         description: Server error
 */

router.post('/client/verify-otp', VerifyOtp);
/**
 * @swagger
 * /auth/client/login:
 *   post:
 *     summary: Client login
 *     tags: [Authentication]
 *     description: >
 *       Logs in a client using email and password.  
 *       Returns client info with access and refresh tokens on success.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: el@gmail.com
 *               password:
 *                 type: string
 *                 example: securePass123
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Login successful
 *               data:
 *                 client:
 *                   name: John
 *                   _id: 6895f83ce8fd2cab75782eb9
 *                   email: el99@gmail.com
 *                   role: client
 *                   isVerified: true
 *                 accessToken: d7e71c975bc5b4ac555415f6c85eeb22:b12848ad43053a039737a2765624a51e5894104eb03426d6745373f089fde5601c77b79292d02d78a3b405c0af1b5ffd901f210b4b5e3fcf3f3ecb7640560f1f35773940c85c26dcf017a8139dc294e3637058923d745576c2e4fa711301ac54580be003d1d485d9a2f53d98c96e7e68f57cbad69a32a715517952ceed7f5ad40a882632e8768e197f5f134b7a670dfcdc720c37c79a7de01018b4fbe02b380d2a23399555efc06f7e679d35ad55fd502ef42e08e650c27c2ef411b574a9f15efe367e278e7bf6058a577249b84aade9
 *                 refreshToken: 8b4e49af2498c51174cd3a7dd8562929:dbb4e7eeed37222e940efdce44966254b5eea3e7112671c5d6c06218f04b81a4dc8cdfe02a75610f23fc469ab90dea0bc677fc1f4f0e8d9a928367ae4018c1ba80b45979c87a3efb1da399a00fc53b81e440193efc794a4551f8ebee586ccfde2e047d2fa550a53bcf9c47cc422f2e3a5448cff49310fb5a4fe4c07dd9a6e4b91afe2b3caca4941a847e06c3c77ede04
 *       401:
 *         description: Unauthorized – invalid email or password
 *       500:
 *         description: Internal server error
 */

router.post('/client/login', loginLimiter, loginValidation, ClientLogin, authMiddleware('client'));


/**
 * @swagger
 * /auth/user/reset-password:
 *   post:
 *     summary: Reset user password
 *     tags: [Authentication]
 *     description: >
 *       Resets the user's password using the `resetTokenId` and `resetCode` sent via email.  
 *       **Important:** The `resetTokenId` must be extracted from the response of the `/auth/user/forgot-password` endpoint and used here.  
 *       The `role` must be set according to the account type:  
 *       - "client" for normal users  
 *       - "driver" for drivers  
 *       - "admin" for administrators
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - resetTokenId
 *               - resetCode
 *               - password
 *               - role
 *             properties:
 *               resetTokenId:
 *                 type: string
 *                 format: uuid
 *                 example: b90d3fa7-d71f-4864-b863-f0f70f160ccd
 *                 description: >
 *                   Token obtained from the forgot-password response, to verify this reset request.
 *               resetCode:
 *                 type: string
 *                 example: "118938"
 *                 description: 6-digit code sent to the user's email.
 *               password:
 *                 type: string
 *                 example: OgElijah
 *                 description: New password to set.
 *               role:
 *                 type: string
 *                 enum: [client, driver, admin]
 *                 example: client
 *                 description: >
 *                   Role of the account. Must correspond to the user type.
 *     responses:
 *       200:
 *         description: Password updated successfully
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Password updated successfully
 *       400:
 *         description: Invalid reset code or token
 *       500:
 *         description: Server error
 */

router.post(
  '/user/reset-password',
  [
    check('resetTokenId').notEmpty().withMessage('Reset token ID required'),
    check('resetCode').isString()
    .matches(/^\d{6}$/)
    .withMessage('Valid 6-digit reset code required'),
    check('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    check('role').isIn(['client', 'driver', 'admin', 'rider']).withMessage('Valid role is required'),
  ],
  UpdatePassword
);
/**
 * @swagger
 * /auth/user/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     description: >
 *       Sends a reset code to the user's email.  
 *       The `resetTokenId` in the response should be extracted and stored by the frontend developer for subsequent reset verification and **should NOT be displayed to the user**.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - role
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: eli@gmail.com
 *               role:
 *                 type: string
 *                 example: client
 *     responses:
 *       200:
 *         description: Reset code sent successfully
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Reset code sent to email.
 *               data:
 *                 resetTokenId: b90d3fa7-d71f-4864-b863-f0f70f160ccd
 *       400:
 *         description: Invalid email or role
 *       500:
 *         description: Server error
 */

router.post(
  '/user/forgot-password',
  [
    check('email').isEmail().withMessage('Valid email is required'),
    check('role').isIn(['client', 'driver', 'admin', 'rider']).withMessage('Valid role is required'),
  ],
  ForgotPassword
);
/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */
/**
 * @swagger
 * tags:
 *   - name: Driver
 *     description: Driver endpoints (uploads, profile, etc.)
 */

/**
 * @swagger
 * /driverAuth/driver/upload-images:
 *   post:
 *     summary: Upload driver license images (front & back)
 *     tags: [Driver]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - frontsideImage
 *               - backsideImage
 *             properties:
 *               frontsideImage:
 *                 type: string
 *                 format: binary
 *                 description: Front side of the driver's license (PNG/JPG). Max 5MB.
 *               backsideImage:
 *                 type: string
 *                 format: binary
 *                 description: Back side of the driver's license (PNG/JPG). Max 5MB.
 *               picture:
 *                 type: string
 *                 format: binary
 *                 description: Optional profile picture (PNG/JPG). Max 5MB.
 *     responses:
 *       '200':
 *         description: Images uploaded successfully
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Images uploaded successfully
 *               data:
 *                 driverId: "6894d38ba348cb50808a6982"
 *                 picture: ""
 *                 frontsideImage: "https://res.cloudinary.com/.../license_f_6894d38...png"
 *                 backsideImage: "https://res.cloudinary.com/.../license_b_6894d38...png"
 *       '400':
 *         description: Bad request - missing files or invalid format
 *       '401':
 *         description: Unauthorized - missing or invalid token
 *       '413':
 *         description: Payload too large (file exceeded size limit)
 *       '500':
 *         description: Internal server error
 */
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage });
router.post('/driver/upload-images', authMiddleware('driver'),
  upload.fields([
    { name: 'picture', maxCount: 1 },
    { name: 'frontsideImage', maxCount: 1 },
    { name: 'backsideImage', maxCount: 1 }
  ]),
  uploadImages
);
/**
 * @swagger
 * tags:
 *   - name: Driver
 *     description: Driver authentication and profile management
 */

/**
 * @swagger
 * /driverAuth/driver/login:
 *   post:
 *     summary: Driver login
 *     description: Authenticates a driver with email and password, returning access and refresh tokens.
 *     tags: [Driver]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: eli@gmail.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: strongPass123
 *     responses:
 *       '200':
 *         description: Login successful
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Login successful
 *               data:
 *                 driver:
 *                   name: John
 *                   _id: 6894d38ba348cb50808a6982
 *                   email: eli@gmail.com
 *                   role: driver
 *                   isVerified: true
 *                 accessToken: "69fe65cf1679184559301c9a72707014:fe21ca6c7b..."
 *                 refreshToken: "0f35d633536aadc5563e45d23fea0bde:ce9b27d3f..."
 *       '400':
 *         description: Bad request - missing or invalid credentials
 *       '401':
 *         description: Unauthorized - incorrect email or password
 *       '500':
 *         description: Internal server error
 */

router.post('/driver/login', DriverLogin, authMiddleware('driver'), loginValidation, loginLimiter);
module.exports = router;
