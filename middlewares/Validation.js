const { body } = require('express-validator');

const registrationValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
  body('FirstName').isString().trim().notEmpty().withMessage('First name is required'),
  body('LastName').isString().trim().notEmpty().withMessage('Last name is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
  body('password').notEmpty().withMessage('Password is required'),
];

const refreshTokenValidation = [
  body('refreshToken').notEmpty().withMessage('Refresh token is required'),
];

module.exports = {
  registrationValidation,
  loginValidation,
  refreshTokenValidation,
};
