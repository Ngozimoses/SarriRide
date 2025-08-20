const {passport} = require('./passport'); // Loads strategies
const express = require('express');
const { rateLimit } = require('express-rate-limit');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');
const redis = require('./Config/redis'); 
const authRoutes = require('./routes/authRoutes'); 
const ClientRideRoutes = require('./routes/clientRide.routes');
const driverRoutes = require ('./routes/auth.Driver.routes'); 
const DriverRidesRoutes = require('./routes/DriverRides.routes')
const path = require('path');

// Initialize Express app
const app = express();
app.use(passport.initialize());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1)
// Logger setup
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

// Environment validation
const validateEnv = () => {
  const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'ENCRYPTION_KEY'];
  const missingEnv = requiredEnv.filter(key => !process.env[key]);
  if (missingEnv.length > 0) {
    logger.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
    throw new Error('Missing required environment variables');
  }
  if (!process.env.REDIS_URL && (!process.env.REDIS_HOST || !process.env.REDIS_PORT)) {
    logger.error('Redis configuration missing: REDIS_URL or REDIS_HOST and REDIS_PORT required');
    throw new Error('Redis configuration missing');
  }
};
// Middleware
app.use(helmet()); // Security headers
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies


// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 requests per IP
  message: { status: 'error', message: 'Too many requests, please try again later' }
});
app.use(globalLimiter);

// MongoDB connection
const connectMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    logger.info('MongoDB connected successfully', { uri: process.env.MONGO_URI });
  } catch (error) {
    logger.error('MongoDB connection error', { error: error.message });
    process.exit(1);
  }
};

// Routes
app.use('/auth', authRoutes);// this is for client authentication
app.use('/clientRide', ClientRideRoutes);
app.use('/driverAuth', driverRoutes);// DRIVER AUTHENTICATION ROUTES
app.use('/driverRides', DriverRidesRoutes); // this is for driver ride routes


const swaggerAuthRoutes = require('./routes/SwaggerGoogleAuth'); // swagger documentation
app.use('/', swaggerAuthRoutes); 

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    await redis.ping(); // Test Redis connection
    await mongoose.connection.db.admin().ping(); // Test MongoDB connection
    res.status(200).json({ status: 'success', message: 'Server is healthy' });
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    res.status(500).json({ status: 'error', message: 'Server is unhealthy' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unexpected error', { error: err.message, stack: err.stack });
  res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
});

// Start server
const PORT = process.env.PORT || 3000;
const startServer = async () => {
  try {
    validateEnv();
    await connectMongoDB();
    app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
    });
  } catch (error) {
    logger.error('Server startup error', { error: error.message });
    process.exit(1);
  }
};
const setupSwagger = require('./swagger');

const open = require('open').default;
setupSwagger(app);
open("https://sarriride.onrender.com/api-docs");

startServer();
