const express = require('express');
const passport = require('passport');
const { rateLimit } = require('express-rate-limit');
const { body, check } = require('express-validator');
const {verifyEmail, verifyDriverOtp, registerDriver, uploadImages} = require('../Controllers/Driver.controller.js');
const {DriverLogin} = require('../Controllers/Driver.controller.js');
const { calculateRidePrice, mapQueryToBody } = require('../Controllers/Client.controller');
const { DriverRefreshToken } = require('../Controllers/Driver.controller.js')
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
const Limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { status: 'error', message: 'Too many requests, please try again later' }
});
const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { status: 'error', message: 'Too many refresh attempts, please try again later' },
});
const {
  ClientRegistration,
  ClientLogin,
  ClientRefreshToken,
  ClientLogout,
  ClientFacebookDataDeletion
} = require('../Controllers/client.auth.controller');
const { checkAvailableDrivers } = require('../Controllers/DriverRides.controller');

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
 * /auth/client/refresh-Token:
 *   post:
 *     summary: Refresh Access Token
 *     tags: [Client Authentication]
 *     description: |
 *       This endpoint allows a **client** to refresh their `accessToken` using a valid `refreshToken`.  
 *       The `refreshToken` is issued during the **initial login** and must be securely stored on the frontend.  
 *
 *       ⚠️ **Important Notes for Frontend Developers:**
 *       - Always pass the `refreshToken` received during login.  
 *       - If the `refreshToken` has expired or is invalid, the client must log in again.  
 *       - The new response will include both a new `accessToken` and a new `refreshToken`.  
 *       - Replace the old tokens with the new ones after each refresh.  
 *
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: >
 *                   The `refreshToken` received during the **initial login**.  
 *                   It is a long, encrypted string and must be stored securely on the client side.  
 *                   Use it to obtain a new `accessToken` without requiring the user to log in again.  
 *                 example: c243420af41a0f2099cf56c931ac6f94:0f3a46296ff05655a93eb2414d26d3fca0dd15ef324a180ed514ee6b3190b5105e56ac0947d12a8882df1212a36c6c02e862dafcd284e35bb0dfd4dba0131493dd45b83e36159f32ab58c407b39598627d57ad97eac2c6e4d703a4eace8b8baf6b9b838a79f85cd6e4899049a6239510b39525bc4d75d180ee9c7c10f4a7153bf2a2648b2a687962b06f29debc373c35
 *     responses:
 *       "200":
 *         description: Successfully refreshed access token
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Access token refreshed
 *               data:
 *                 client:
 *                   name: SarriRide
 *                   _id: 68a49cf858e6443d3ed85f0f
 *                   email: sarriRide@gmail.com
 *                   role: client
 *                   isVerified: true
 *                 accessToken: 3978c826adb39be102aba90800db353c:70563d3630aa404f40333e38a94d57615a2e30ffd8b57ed4c7e0b226369dcba0acfa34773daa9e1761c5d020f8225c5091c30e43195140d834d72f667794bd092809c52077a4e5fdf9167e598d54c9abd8db0d7699bb0bec38ed7ac4e0cdb312072ec87729e9326400fd91bb530c3334e63885901fbb7af383edbba60de2db2d8de99cb4b56eec62cfda4ecaf0792b2c423e2ea7aa028062ae2746797cea54c6cc1614acd6253a8a048e5bb57b96ac1012fb1ec9eedad47ba43cebb880fc6e980a644010f967cca090e98ccca0943121
 *                 refreshToken: 05393587823329736b77e63eecaf8469:6325aee7c666ea10d60a310764f4bf32bd0a9032ba9afb5680078d57643bf12cdd0602693e032e4a3ed9bffd011c84bae155506984d00abc0b08a3ac4d173224e3429cbb5ab2ee6c5a1c353d267669e815e81ed919578685544a32b00c740db0f32a4b5ff0328d5adc7db74331a4bb5f8c9cf16a81603d594e4f3e32bc0cc213a34d1664324583c79b135c0b831dad6f
 *       "400":
 *         description: Invalid request or refresh token missing
 *       "401":
 *         description: Unauthorized – Invalid or expired refresh token
 *       "500":
 *         description: Server error
 */

router.post('/client/refresh-token', refreshLimiter, refreshTokenValidation, ClientRefreshToken);

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
/**
 * @swagger
 * /driverAuth/driver/verifyDriverEmail:
 *   post:
 *     summary: Verify driver email before registration
 *     description: Sends an OTP to the provided email address to verify it before continuing with driver registration.
 *     tags: [Driver]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: eli@gmail.com
 *     responses:
 *       '200':
 *         description: OTP sent successfully
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: OTP sent to email for verification
 *               data:
 *                 driverId: 689758c6e5a596b9d2380e3c
 *                 email: eli@gmail.com
 *       '400':
 *         description: Bad request - invalid or missing email
 *       '409':
 *         description: Conflict - email already registered
 *       '500':
 *         description: Internal server error
 */
router.post('/driver/verifyDriverEmail', [
  check('email').isEmail().withMessage('Valid email is required'),
], verifyEmail);
/**
 * @swagger
 * /driverAuth/driver/verifyDriverOtp:
 *   post:
 *     summary: Verify OTP sent to driver's email
 *     description: Confirms the OTP sent to the driver's email to verify identity before completing registration.
 *     tags: [Driver]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - otp
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: elijayboy87@gmail.com
 *               otp:
 *                 type: string
 *                 description: 6-digit one-time password sent to the email
 *                 example: "483957"
 *     responses:
 *       '200':
 *         description: OTP verified successfully
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Email verified successfully. Proceed to complete registration.
 *               data:
 *                 driverId: 689758c6e5a596b9d2380e3c
 *                 email: elijayboy87@gmail.com
 *       '400':
 *         description: Invalid or expired OTP
 *       '404':
 *         description: Email not found
 *       '500':
 *         description: Internal server error
 */
router.post('/driver/verifyDriverOtp', [
  check('email').isEmail().withMessage('Valid email is required'),
  check('otp').isNumeric().withMessage('Valid OTP is required'),
], verifyDriverOtp);

/**
 * @swagger
 * /driverAuth/driver/register:
 *   post:
 *     summary: Register a new driver
 *     description: Completes the driver registration process after email verification. Requires driver personal details, license details, address, emergency contact, bank details, and vehicle information.
 *     tags: [Driver]
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
 *               - phoneNumber
 *               - DateOfBirth
 *               - Gender
 *               - licenseNumber
 *               - drivingLicense
 *               - currentAddress
 *               - permanentAddress
 *               - emergencyContactNumber
 *               - bankDetails
 *               - vehicleDetails
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: eli@gmail.com
 *               FirstName:
 *                 type: string
 *                 example: John
 *               LastName:
 *                 type: string
 *                 example: Doe
 *               password:
 *                 type: string
 *                 format: password
 *                 example: strongPass123
 *               phoneNumber:
 *                 type: string
 *                 example: +2348012345678
 *               DateOfBirth:
 *                 type: string
 *                 format: date
 *                 example: 1990-05-15
 *               Gender:
 *                 type: string
 *                 enum: [male, female, other]
 *                 example: male
 *               licenseNumber:
 *                 type: string
 *                 example: DL1234567890
 *               drivingLicense:
 *                 type: object
 *                 required:
 *                   - issueDate
 *                   - expiryDate
 *                 properties:
 *                   issueDate:
 *                     type: string
 *                     format: date
 *                     example: 2015-04-01
 *                   expiryDate:
 *                     type: string
 *                     format: date
 *                     example: 2029-04-01
 *               currentAddress:
 *                 type: object
 *                 properties:
 *                   address: { type: string, example: 123 Main Street }
 *                   state: { type: string, example: Lagos }
 *                   city: { type: string, example: Ikeja }
 *                   country: { type: string, example: Nigeria }
 *                   postalCode: { type: string, example: 100001 }
 *               permanentAddress:
 *                 type: object
 *                 properties:
 *                   address: { type: string, example: 456 Elm Street }
 *                   state: { type: string, example: Lagos }
 *                   city: { type: string, example: Surulere }
 *                   country: { type: string, example: Nigeria }
 *                   postalCode: { type: string, example: 100002 }
 *               emergencyContactNumber:
 *                 type: string
 *                 example: +2348098765432
 *               bankDetails:
 *                 type: object
 *                 properties:
 *                   bankAccountNumber: { type: string, example: 0123456789 }
 *                   bankName: { type: string, example: First Bank }
 *                   bankAccountName: { type: string, example: John Doe }
 *               vehicleDetails:
 *                 type: object
 *                 properties:
 *                   make: { type: string, example: Toyota }
 *                   model: { type: string, example: Corolla }
 *                   year: { type: integer, example: 2018 }
 *                   licensePlate: { type: string, example: LAG123XY }
 *     responses:
 *       '200':
 *         description: Driver registered successfully
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Driver registered successfully. Awaiting admin verification.
 *               data:
 *                 driverId: 689758c6e5a596b9d2380e3c
 *                 email: elijayboy87@gmail.com
 *       '400':
 *         description: Invalid request data
 *       '401':
 *         description: Unauthorized or email not verified
 *       '500':
 *         description: Internal server error
 */


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
], registerDriver);

/**
 * @swagger
 * /clientRide/checkingAvailableDrivers:
 *   post:
 *     summary: Check available drivers and pricing for a ride
 *     description: Retrieves available drivers around the client based on their current location and destination, along with pricing details by category.
 *     tags:
 *       - Client Ride
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentLocation
 *               - destination
 *             properties:
 *               currentLocation:
 *                 type: object
 *                 properties:
 *                   latitude:
 *                     type: number
 *                     example: 41.8781
 *                   longitude:
 *                     type: number
 *                     example: -87.6298
 *               destination:
 *                 type: object
 *                 properties:
 *                   latitude:
 *                     type: number
 *                     example: 29.7604
 *                   longitude:
 *                     type: number
 *                     example: -95.3698
 *     responses:
 *       200:
 *         description: Successfully retrieved available drivers and pricing details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                   example: Available drivers and pricing details retrieved
 *                 data:
 *                   type: object
 *                   properties:
 *                     distanceKm:
 *                       type: number
 *                       example: 1743.485
 *                     categoryDetails:
 *                       type: object
 *                       properties:
 *                         luxury:
 *                           type: object
 *                           properties:
 *                             price:
 *                               type: number
 *                               example: 5230955
 *                             seats:
 *                               type: integer
 *                               example: 4
 *                             availableDriversCount:
 *                               type: integer
 *                               example: 1
 *                             availableDrivers:
 *                               type: array
 *                               items:
 *                                 type: object
 *                                 properties:
 *                                   _id:
 *                                     type: string
 *                                     example: 689758c6e5a596b9d2380e3c
 *                                   name:
 *                                     type: string
 *                                     example: John Doe
 *                                   location:
 *                                     type: object
 *                                     properties:
 *                                       type:
 *                                         type: string
 *                                         example: Point
 *                                       coordinates:
 *                                         type: array
 *                                         items:
 *                                           type: number
 *                                         example: [-87.6298, 41.8781]
 *                         xl:
 *                           type: object
 *                           properties:
 *                             price:
 *                               type: number
 *                               example: 4184864
 *                             seats:
 *                               type: integer
 *                               example: 7
 *                             availableDriversCount:
 *                               type: integer
 *                               example: 0
 *                             availableDrivers:
 *                               oneOf:
 *                                 - type: string
 *                                   example: No available drivers for this destination
 *                                 - type: array
 *                                   items:
 *                                     type: object
 *                         comfort:
 *                           type: object
 *                           properties:
 *                             price:
 *                               type: number
 *                               example: 3487470
 *                             seats:
 *                               type: integer
 *                               example: 4
 *                             availableDriversCount:
 *                               type: integer
 *                               example: 0
 *                             availableDrivers:
 *                               oneOf:
 *                                 - type: string
 *                                   example: No available drivers for this destination
 *                                 - type: array
 *                                   items:
 *                                     type: object
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized (missing or invalid token)
 *       500:
 *         description: Internal server error
 */
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
/**
 * @swagger
 * paths:
 *   /clientRide/calculate-price:
 *     post:
 *       summary: Calculate ride price
 *       description: Calculates the ride price between the client's current location and destination.
 *       tags:
 *         - Ride
 *       security:
 *         - bearerAuth: []
 *       requestBody:
 *         required: true
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               required:
 *                 - currentLocation
 *                 - destination
 *               properties:
 *                 currentLocation:
 *                   type: object
 *                   required:
 *                     - latitude
 *                     - longitude
 *                   properties:
 *                     latitude:
 *                       type: number
 *                       format: float
 *                       minimum: -90
 *                       maximum: 90
 *                       example: 41.8781
 *                     longitude:
 *                       type: number
 *                       format: float
 *                       minimum: -180
 *                       maximum: 180
 *                       example: -87.6298
 *                 destination:
 *                   type: object
 *                   required:
 *                     - latitude
 *                     - longitude
 *                   properties:
 *                     latitude:
 *                       type: number
 *                       format: float
 *                       minimum: -90
 *                       maximum: 90
 *                       example: 29.7604
 *                     longitude:
 *                       type: number
 *                       format: float
 *                       minimum: -180
 *                       maximum: 180
 *                       example: -95.3698
 *       responses:
 *         '200':
 *           description: Ride price calculated successfully
 *           content:
 *             application/json:
 *               schema:
 *                 type: object
 *                 properties:
 *                   status:
 *                     type: string
 *                     example: success
 *                   message:
 *                     type: string
 *                     example: Ride prices calculated
 *                   data:
 *                     type: object
 *                     properties:
 *                       distanceKm:
 *                         type: number
 *                         example: 1743.485
 *                       prices:
 *                         type: object
 *                         properties:
 *                           luxury:
 *                             type: object
 *                             properties:
 *                               price:
 *                                 type: number
 *                                 example: 5230955
 *                               seats:
 *                                 type: integer
 *                                 example: 4
 *                           xl:
 *                             type: object
 *                             properties:
 *                               price:
 *                                 type: number
 *                                 example: 4184864
 *                               seats:
 *                                 type: integer
 *                                 example: 7
 *                           comfort:
 *                             type: object
 *                             properties:
 *                               price:
 *                                 type: number
 *                                 example: 3487470
 *                               seats:
 *                                 type: integer
 *                                 example: 4
 *         '400':
 *           description: Invalid request body (validation error)
 *         '401':
 *           description: Unauthorized (missing/invalid token)
 *         '429':
 *           description: Too many requests (rate limited)
 *         '500':
 *           description: Internal server error
 */
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


/**
 * @swagger
 * tags:
 *   name: Driver WebSocket
 *   description: Real-time WebSocket connection for driver location + availability
 */

/**
 * @swagger
 * /driver/websocket:
 *   get:
 *     summary: WebSocket connection (Driver only)
 *     tags: [Driver WebSocket]
 *     description: |
 *       ⚠️ Note: `/driver/websocket` is **not a real REST endpoint**.  
 *       It exists only to document the WebSocket connection for drivers.  
 *
 *       Drivers connect to the **Socket.IO server** for live location + availability updates.  
 *       The connection is established via **WebSocket** with query parameters.  
 *
 *       Example connection URL:
 *       ```
 *       wss://sarriride.onrender.com?token=<ACCESS_TOKEN>&ETO=4&transport=websocket
 *       ```
 *
 *       **Origin header** (required):
 *       ```
 *       origin: https://sarriride.onrender.com
 *       ```
 *
 *       ### Query Parameters:
 *       - `token` (string, required): Driver `accessToken` returned at login (`data.accessToken`).  
 *       - `ETO` (integer, optional): Engine.IO parameter (use `4`).  
 *       - `transport` (string, required): Must be `"websocket"`.  
 *
 *       ---
 *
 *       ### Event: `updateLocation`
 *       **Client → Server**
 *       ```json
 *       {
 *         "latitude": 40.7128,
 *         "longitude": -74.0060,
 *         "availabilityStatus": "available"
 *       }
 *       ```
 *
 *       - When the driver goes **online** → send `"available"`.  
 *       - When the driver is **booked/accepts a ride** → send `"on_trip"`.  
 *       - When the driver goes **offline** → send `"unavailable"`.  
 *
 *       ⚡ Send periodically (every 5–10s) or on meaningful movement.
 *
 *       ---
 *
 *       ### Example Server Response
 *       ```json
 *       {
 *         "status": "success",
 *         "message": "Location updated successfully",
 *         "data": {
 *           "location": {
 *             "type": "Point",
 *             "coordinates": [-74.0060, 40.7128]
 *           },
 *           "availabilityStatus": "available",
 *           "lastLocationUpdate": "2025-08-23T13:55:59.371Z"
 *         }
 *       }
 *       ```
 *     responses:
 *       '101':
 *         description: WebSocket upgrade successful
 */

/**
 * @swagger
 * /driverAuth/driver/refresh-token:
 *   post:
 *     summary: Refresh Driver Access Token
 *     tags: [Driver Authentication]
 *     description: |
 *       This endpoint allows a **driver** to refresh their `accessToken` using a valid `refreshToken`.  
 *       The `refreshToken` is issued during the **initial driver login** and must be securely stored on the frontend.  
 *
 *       ⚠️ **Important Notes for Frontend Developers:**
 *       - Always pass the `refreshToken` received during driver login.  
 *       - If the `refreshToken` has expired or is invalid, the driver must log in again.  
 *       - The new response will include both a new `accessToken` and a new `refreshToken`.  
 *       - Replace the old tokens with the new ones after each refresh.  
 *
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: >
 *                   The `refreshToken` received during the **driver login**.  
 *                   It is a long, encrypted string and must be stored securely on the client side.  
 *                   Use it to obtain a new `accessToken` without requiring the driver to log in again.  
 *                 example: 0826fbec11f8f8e969b0c8dbf2dd1c2b:f8c02549c273b9dba65b94cc610aeafc5baddef35fe4ce4e7a4f04c249e7ff94b33e89c5738e1bd461b39ef466ba57a49456c64c7243389285b8eb40c26060756ca090a8d4932e972426138fbe2707533e2d25b361f8b4fd9713077a73e210ec43fabd0c81a30c8407a2f9f65766bdd637666e53cfc2169c4d165986f8e1445b8cf10bca61c5227eb5b36c3b0912e96
 *     responses:
 *       "200":
 *         description: Successfully refreshed driver access token
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               message: Access token refreshed
 *               data:
 *                 driver:
 *                   name: John
 *                   _id: 689758c6e5a596b9d2380e3c
 *                   email: elijayboy87@gmail.com
 *                   role: driver
 *                   isVerified: true
 *                 accessToken: 560da709694a3b9f335e0a6c38759265:df7e38fe8cf7c4a2f603fbca0cbfd87b69d7ff0255c4d349dc4b7b3d7f77db32f941b5a53327978da6350bae9ba4d5691a999bb5a817939fb264f582ae87c66c0e71a569142945559e38af722c533e0e237215d569202daec3fe290eed1f2f9c224da20f428242a9684636556e31ef07f7e7e68059bcb644e74f64c29d98083523358a19d252d787dca439bb4cf3efc71038bbb8f853a7f96e4724e1dd9590a6613eb709e3e712142fd7a9c2eac9cb750c8093befde444a3f2835737fafee3fa693a42ef24320d76ac12357ebcd86aa4
 *                 refreshToken: c0ddf1129d0ff9f9393e9c56e7ccebaa:c269fb7e5dd05590b5b0a7203c5c6fed88de58dfeaed67b57614059b240276488fe92b7d4c89861d4bb24f3a55b53cc08bf0015ff6d576071140b32461778d44877e5fc92d6e3916ec0bf731114c725dc3e91c1fe795648d46921d495b9da56d1b826b5774286a91310a11511e29cf1cac1f1592d43af65c45646df53ea50cd47594277dde779d785f94d6bae175ee3f
 *       "400":
 *         description: Invalid request or refresh token missing
 *       "401":
 *         description: Unauthorized – Invalid or expired refresh token
 *       "500":
 *         description: Server error
 */
router.post('/driver/refresh-token', refreshTokenValidation,refreshLimiter,DriverRefreshToken);

module.exports = router;
