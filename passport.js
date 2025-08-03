const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const Client = require('./models/Client');
const winston = require('winston');
const redis = require('./Config/redis');
const sanitizeHtml = require('sanitize-html');
const jwt = require('jsonwebtoken');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

const CONFIG = {
  REDIS_KEY_PREFIX: 'auth:',
  USER_CACHE_TTL: 3600, // 1 hour
  STATE_TOKEN_EXPIRY: '5m', // Short-lived state token
};

// Validate environment variables
const validateEnv = () => {
  const requiredEnv = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI', 'FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET', 'FACEBOOK_REDIRECT_URI', 'JWT_SECRET'];
  const missingEnv = requiredEnv.filter(key => !process.env[key]);
  if (missingEnv.length > 0) {
    logger.error(`Missing OAuth environment variables: ${missingEnv.join(', ')}`);
    throw new Error(`Missing OAuth environment variables: ${missingEnv.join(', ')}`);
  }
};

// Generate JWT-based state token
const generateStateToken = (data) => {
  return jwt.sign(data, process.env.JWT_SECRET, { expiresIn: CONFIG.STATE_TOKEN_EXPIRY });
};

// Validate JWT-based state token
const validateStateToken = (state) => {
  try {
    return jwt.verify(state, process.env.JWT_SECRET);
  } catch (error) {
    logger.warn('Invalid state token', { error: error.message });
    return null;
  }
};

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_REDIRECT_URI,
  scope: ['profile', 'email'],
  passReqToCallback: true,
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    // Validate state token
    const state = validateStateToken(req.query.state);
    if (!state || state.authType !== 'google') {
      logger.warn('Invalid or missing Google state token', { profileId: profile.id });
      return done(new Error('Invalid state token'), null);
    }

    const sanitizedEmail = profile.emails[0].value.toLowerCase().trim();
    const sanitizedFirstName = sanitizeHtml(profile.name.givenName || 'User');
    const sanitizedLastName = sanitizeHtml(profile.name.familyName || '');

    // Check Redis for existing user
    const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${sanitizedEmail}:client`;
    let client = await redis.get(cacheKey);
    if (client) {
      client = JSON.parse(client);
      if (client.googleId === profile.id) {
        logger.info('Google login: User found in Redis cache', { email: sanitizedEmail });
        return done(null, client);
      }
    }

    // Check MongoDB for existing user
    client = await Client.findOne({ $or: [{ googleId: profile.id }, { email: sanitizedEmail }] }).lean();
    if (client) {
      if (!client.googleId) {
        // Link Google account to existing email-based account
        client = await Client.findOneAndUpdate(
          { email: sanitizedEmail },
          { googleId: profile.id, isVerified: true },
          { new: true }
        ).lean();
        logger.info('Google account linked to existing client', { email: sanitizedEmail });
      }
      await redis.set(cacheKey, JSON.stringify(client), 'EX', CONFIG.USER_CACHE_TTL);
      return done(null, client);
    }

    // Create new client
    const newClient = new Client({
      email: sanitizedEmail,
      googleId: profile.id,
      FirstName: sanitizedFirstName,
      LastName: sanitizedLastName,
      role: 'client',
      isVerified: true, // Google-verified email
    });
    await newClient.save();
    await redis.set(cacheKey, JSON.stringify(newClient.toObject()), 'EX', CONFIG.USER_CACHE_TTL);
    logger.info('Google client registered', { email: sanitizedEmail });
    done(null, newClient);
  } catch (error) {
    logger.error('Google OAuth error', { error: error.message, profileId: profile.id });
    done(error, null);
  }
}));

// Facebook OAuth Strategy
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: process.env.FACEBOOK_REDIRECT_URI,
  profileFields: ['id', 'emails', 'name'],
  passReqToCallback: true,
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    // Validate state token
    const state = validateStateToken(req.query.state);
    if (!state || state.authType !== 'facebook') {
      logger.warn('Invalid or missing Facebook state token', { profileId: profile.id });
      return done(new Error('Invalid state token'), null);
    }

    const sanitizedEmail = profile.emails ? profile.emails[0].value.toLowerCase().trim() : `${profile.id}@facebook.com`;
    const sanitizedFirstName = sanitizeHtml(profile.name.givenName || 'User');
    const sanitizedLastName = sanitizeHtml(profile.name.familyName || '');

    // Check Redis for existing user
    const cacheKey = `${CONFIG.REDIS_KEY_PREFIX}user:${sanitizedEmail}:client`;
    let client = await redis.get(cacheKey);
    if (client) {
      client = JSON.parse(client);
      if (client.facebookId === profile.id) {
        logger.info('Facebook login: User found in Redis cache', { email: sanitizedEmail });
        return done(null, client);
      }
    }

    // Check MongoDB for existing user
    client = await Client.findOne({ $or: [{ facebookId: profile.id }, { email: sanitizedEmail }] }).lean();
    if (client) {
      if (!client.facebookId) {
        // Link Facebook account to existing email-based account
        client = await Client.findOneAndUpdate(
          { email: sanitizedEmail },
          { facebookId: profile.id, isVerified: profile.emails ? true : client.isVerified },
          { new: true }
        ).lean();
        logger.info('Facebook account linked to existing client', { email: sanitizedEmail });
      }
      await redis.set(cacheKey, JSON.stringify(client), 'EX', CONFIG.USER_CACHE_TTL);
      return done(null, client);
    }

    // Create new client
    const newClient = new Client({
      email: sanitizedEmail,
      facebookId: profile.id,
      FirstName: sanitizedFirstName,
      LastName: sanitizedLastName,
      role: 'client',
      isVerified: profile.emails ? true : false,
    });
    await newClient.save();
    await redis.set(cacheKey, JSON.stringify(newClient.toObject()), 'EX', CONFIG.USER_CACHE_TTL);
    logger.info('Facebook client registered', { email: sanitizedEmail });
    done(null, newClient);
  } catch (error) {
    logger.error('Facebook OAuth error', { error: error.message, profileId: profile.id });
    done(error, null);
  }
}));

validateEnv();

module.exports = {
  passport,
  generateStateToken,
};
