
// const { passport } = require('./passport'); // Loads strategies
// const express = require('express');
// const { rateLimit } = require('express-rate-limit');
// const mongoose = require('mongoose');
// const helmet = require('helmet');
// const cors = require('cors');
// const winston = require('winston');
// const redis = require('./Config/redis'); 
// const authRoutes = require('./routes/authRoutes'); 
// const ClientRideRoutes = require('./routes/clientRide.routes');
// const driverRoutes = require('./routes/auth.Driver.routes'); 
// const DriverRidesRoutes = require('./routes/DriverRides.routes');
// const path = require('path');
// // ADDED FOR SOCKET.IO
// const http = require('http');
// const { Server } = require('socket.io');
// const { setupSocketIO } = require('./Controllers/UpdateLocation.controller');
// const { authMiddlewareSocket } = require('./middlewares/auth');

// // Initialize Express app
// const app = express();
// // ADDED FOR SOCKET.IO FOR LIVE UPDATE IMPLEMENTATION
// const server = http.createServer(app);
// const io = new Server(server, {
//   cors: {
//     origin: process.env.CORS_ORIGIN || '*',
//     methods: ['GET', 'POST'],
//     credentials: true
//   }
// });
// // ADDED FOR SOCKET.IO: Redis adapter setup
// const { createAdapter } = require('@socket.io/redis-adapter');
// const pubClient = redis;
// const subClient = pubClient.duplicate();
// io.adapter(createAdapter(pubClient, subClient));

// // ADDED FOR SOCKET.IO: Initialize Socket.IO handlers
// io.use(authMiddlewareSocket('driver'));
// setupSocketIO(io);

// app.use(passport.initialize());
// app.use(express.static(path.join(__dirname, 'public')));
// app.set('trust proxy', 1);
// // Logger setup
// const logger = winston.createLogger({
//   level: 'info',
//   format: winston.format.combine(
//     winston.format.timestamp(),
//     winston.format.json()
//   ),
//   transports: [
//     new winston.transports.Console(),
//     new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
//     new winston.transports.File({ filename: 'logs/combined.log' })
//   ]
// });

// // Environment validation
// const validateEnv = () => {
//   const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'ENCRYPTION_KEY'];
//   const missingEnv = requiredEnv.filter(key => !process.env[key]);
//   if (missingEnv.length > 0) {
//     logger.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
//     throw new Error('Missing required environment variables');
//   }
//   if (!process.env.REDIS_URL && (!process.env.REDIS_HOST || !process.env.REDIS_PORT)) {
//     logger.error('Redis configuration missing: REDIS_URL or REDIS_HOST and REDIS_PORT required');
//     throw new Error('Redis configuration missing');
//   }
// };

// // Middleware
// app.use(helmet()); // Security headers
// app.use(cors({
//   origin: process.env.CORS_ORIGIN || '*',
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   credentials: true
// }));
// app.use(express.json()); // Parse JSON bodies
// app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// // Global rate limiter
// const globalLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // Max 100 requests per IP
//   message: { status: 'error', message: 'Too many requests, please try again later' }
// });
// app.use(globalLimiter);

// // MongoDB connection
// const connectMongoDB = async () => {
//   try {
//     await mongoose.connect(process.env.MONGO_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     logger.info('MongoDB connected successfully', { uri: process.env.MONGO_URI });
//   } catch (error) {
//     logger.error('MongoDB connection error', { error: error.message });
//     process.exit(1);
//   }
// };

// // Routes
// app.use('/auth', authRoutes); // this is for client authentication
// app.use('/clientRide', ClientRideRoutes);
// app.use('/driverAuth', driverRoutes); // DRIVER AUTHENTICATION ROUTES
// app.use('/driverRides', DriverRidesRoutes); // this is for driver ride routes

// const swaggerAuthRoutes = require('./routes/SwaggerGoogleAuth'); // swagger documentation
// app.use('/', swaggerAuthRoutes); 

// // Health check endpoint
// app.get('/health', async (req, res) => {
//   try {
//     await redis.ping(); // Test Redis connection
//     await mongoose.connection.db.admin().ping(); // Test MongoDB connection
//     res.status(200).json({ status: 'success', message: 'Server is healthy' });
//   } catch (error) {
//     logger.error('Health check failed', { error: error.message });
//     res.status(500).json({ status: 'error', message: 'Server is unhealthy' });
//   }
// });

// // Error handling middleware
// app.use((err, req, res, next) => {
//   logger.error('Unexpected error', { error: err.message, stack: err.stack });
//   res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
// });

// // Start server
// const PORT = process.env.PORT || 3000;
// const startServer = async () => {
//   try {
//     validateEnv();
//     await connectMongoDB();
//     // ADDED FOR SOCKET.IO: Use server.listen instead of app.listen
//     server.listen(PORT, () => {
//       logger.info(`Server running on port ${PORT}`);
//     });
//   } catch (error) {
//     logger.error('Server startup error', { error: error.message });
//     process.exit(1);
//   }
// };

// const setupSwagger = require('./swagger');
// const open = require('open').default;
// setupSwagger(app);
// open("https://sarriride.onrender.com/api-docs");

// startServer();

const { passport } = require('./passport');
const express = require('express');
const { rateLimit } = require('express-rate-limit');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');
const redis = require('./Config/redis');
const authRoutes = require('./routes/authRoutes');
const ClientRideRoutes = require('./routes/clientRide.routes');
const driverRoutes = require('./routes/auth.Driver.routes');
const DriverRidesRoutes = require('./routes/DriverRides.routes');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const { createAdapter } = require('@socket.io/redis-adapter');
const { setupSocketIO } = require('./Controllers/UpdateLocation.controller');
const { authMiddlewareSocket } = require('./middlewares/auth');
const admin = require('./Config/firebase');
const DailyRotateFile = require('winston-daily-rotate-file');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  path: '/socket.io/',
  cors: {
    origin: process.env.CORS_ORIGIN || 'https://sarriride.onrender.com', // Restrict in production
    methods: ['GET', 'POST'],
    credentials: true
  }
});

const pubClient = redis;
const subClient = pubClient.duplicate();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new DailyRotateFile({ filename: 'logs/combined-%DATE%.log', datePattern: 'YYYY-MM-DD' })
  ]
});

async function setupRedisAdapter() {
  try {
    await pubClient.ping();
    await subClient.ping();
    io.adapter(createAdapter(pubClient, subClient));
    logger.info('Redis adapter setup successfully');
  } catch (error) {
    logger.error('Redis adapter setup failed', { error: error.message });
    process.exit(1);
  }
}

io.use((socket, next) => {
  logger.info('Socket.IO connection attempt', { socketId: socket.id });
  authMiddlewareSocket('driver')(socket, next);
});

io.on('connection', (socket) => {
  logger.info('Socket.IO client connected', { socketId: socket.id, driverId: socket.user?._id });
  setupSocketIO(io, socket);
  socket.on('disconnect', () => logger.info('Socket.IO client disconnected', { socketId: socket.id, driverId: socket.user?._id }));
});

app.set('admin', admin);
app.set('io', io);
app.use(passport.initialize());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1);

const validateEnv = () => {
  const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'ENCRYPTION_KEY'];
  const missingEnv = requiredEnv.filter(key => !process.env[key]);
  if (missingEnv.length > 0) {
    logger.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
    throw new Error('Missing required environment variables');
  }
  if (!process.env.REDIS_URL && (!process.env.REDIS_HOST || !process.env.REDIS_PORT)) {
    logger.error('Redis configuration missing');
    throw new Error('Redis configuration missing');
  }
};

app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'https://sarriride.onrender.com',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { status: 'error', message: 'Too many requests, please try again later' }
});
app.use(globalLimiter);

const connectMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10 // Add connection pooling
    });
    logger.info('MongoDB connected successfully', { uri: process.env.MONGO_URI });
  } catch (error) {
    logger.error('MongoDB connection error', { error: error.message });
    process.exit(1);
  }
};

app.use('/auth', authRoutes);
app.use('/clientRide', ClientRideRoutes);
app.use('/driverAuth', driverRoutes);
app.use('/driverRides', DriverRidesRoutes);
app.use('/', require('./routes/SwaggerGoogleAuth'));

app.get('/health', async (req, res) => {
  try {
    await redis.ping();
    await mongoose.connection.db.admin().ping();
    res.status(200).json({ status: 'success', message: 'Server is healthy' });
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    res.status(500).json({ status: 'error', message: 'Server is unhealthy' });
  }
});

app.use((err, req, res, next) => {
  logger.error('Unexpected error', { error: err.message, stack: err.stack });
  res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
});

const setupSwagger = require('./swagger');
const open = require('open').default;

const startServer = async () => {
  try {
    validateEnv();
    await connectMongoDB();
    await setupRedisAdapter();
    setupSwagger(app);
    server.listen(process.env.PORT || 3000, () => {
      logger.info(`Server running on port ${process.env.PORT || 3000}`);
      open("https://sarriride.onrender.com/api-docs");
    });
  } catch (error) {
    logger.error('Server startup error', { error: error.message });
    process.exit(1);
  }
};

process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down');
  await mongoose.connection.close();
  server.close(() => process.exit(0));
});

startServer();



//this would be revisited as the current 
// const { passport } = require('./passport');
// const express = require('express');
// const { rateLimit } = require('express-rate-limit');
// const mongoose = require('mongoose');
// const helmet = require('helmet');
// const cors = require('cors');
// const winston = require('winston');
// const redis = require('./Config/redis');
// const authRoutes = require('./routes/authRoutes');
// const ClientRideRoutes = require('./routes/clientRide.routes');
// const driverRoutes = require('./routes/auth.Driver.routes');
// const DriverRidesRoutes = require('./routes/DriverRides.routes');
// const path = require('path');
// const http = require('http');
// const { Server } = require('socket.io');
// const { setupSocketIO } = require('./Controllers/UpdateLocation.controller');
// const { authMiddlewareSocket } = require('./middlewares/auth');
// const admin = require('./Config/firebase')

// const app = express();
// const server = http.createServer(app);
// const io = new Server(server, {
//   path: '/socket.io/',
//   cors: {
//     origin: process.env.CORS_ORIGIN || '*',
//     methods: ['GET', 'POST'],
//     credentials: true
//   }
// });

// const { createAdapter } = require('@socket.io/redis-adapter');
// const pubClient = redis;
// const subClient = pubClient.duplicate();

// const logger = winston.createLogger({
//   level: 'info',
//   format: winston.format.combine(
//     winston.format.timestamp(),
//     winston.format.json()
//   ),
//   transports: [
//     new winston.transports.Console(),
//     new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
//     new winston.transports.File({ filename: 'logs/combined.log' })
//   ]
// });

// async function setupRedisAdapter() {
//   try {
//     await pubClient.ping();
//     await subClient.ping();
//     io.adapter(createAdapter(pubClient, subClient));
//     logger.info('Redis adapter setup successfully');
//   } catch (error) {
//     logger.error('Redis adapter setup failed', { error: error.message });
//     process.exit(1);
//   }
// }

// io.use((socket, next) => {
//   logger.info('Socket.IO connection attempt', { socketId: socket.id });
//   authMiddlewareSocket('driver')(socket, next);
// });

// io.on('connection', (socket) => {
//   logger.info('Socket.IO client connected', { socketId: socket.id, driverId: socket.user?._id });
//   setupSocketIO(io, socket);
//   socket.on('disconnect', () => logger.info('Socket.IO client disconnected', { socketId: socket.id, driverId: socket.user?._id }));
// });
// app.set('admin', admin);
// app.set("io", io);
// app.use(passport.initialize());
// app.use(express.static(path.join(__dirname, 'public')));
// app.set('trust proxy', 1);

// const validateEnv = () => {
//   const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'ENCRYPTION_KEY'];
//   const missingEnv = requiredEnv.filter(key => !process.env[key]);
//   if (missingEnv.length > 0) {
//     logger.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
//     throw new Error('Missing required environment variables');
//   }
//   if (!process.env.REDIS_URL && (!process.env.REDIS_HOST || !process.env.REDIS_PORT)) {
//     logger.error('Redis configuration missing');
//     throw new Error('Redis configuration missing');
//   }
// };

// app.use(helmet());
// app.use(cors({
//   origin: process.env.CORS_ORIGIN || '*',
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   credentials: true
// }));
// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));

// const globalLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100,
//   message: { status: 'error', message: 'Too many requests, please try again later' }
// });
// app.use(globalLimiter);

// const connectMongoDB = async () => {
//   try {
//     await mongoose.connect(process.env.MONGO_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     logger.info('MongoDB connected successfully', { uri: process.env.MONGO_URI });
//   } catch (error) {
//     logger.error('MongoDB connection error', { error: error.message });
//     process.exit(1);
//   }
// };

// app.use('/auth', authRoutes);
// app.use('/clientRide', ClientRideRoutes);
// app.use('/driverAuth', driverRoutes);
// app.use('/driverRides', DriverRidesRoutes);
// app.use('/', require('./routes/SwaggerGoogleAuth'));

// app.get('/health', async (req, res) => {
//   try {
//     await redis.ping();
//     await mongoose.connection.db.admin().ping();
//     res.status(200).json({ status: 'success', message: 'Server is healthy' });
//   } catch (error) {
//     logger.error('Health check failed', { error: error.message });
//     res.status(500).json({ status: 'error', message: 'Server is unhealthy' });
//   }
// });

// app.use((err, req, res, next) => {
//   logger.error('Unexpected error', { error: err.message, stack: err.stack });
//   res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
// });

// const setupSwagger = require('./swagger');
// const open = require('open').default;

// const startServer = async () => {
//   try {
//     validateEnv();
//     await connectMongoDB();
//     await setupRedisAdapter();
//     setupSwagger(app);
//     server.listen(process.env.PORT || 3000, () => {
//       logger.info(`Server running on port ${process.env.PORT || 3000}`);
//       open("https://sarriride.onrender.com/api-docs");
//     });
//   } catch (error) {
//     logger.error('Server startup error', { error: error.message });
//     process.exit(1);
//   }
// };

// startServer();








// const {passport} = require('./passport'); // Loads strategies
// const express = require('express');
// const { rateLimit } = require('express-rate-limit');
// const mongoose = require('mongoose');
// const helmet = require('helmet');
// const cors = require('cors');
// const winston = require('winston');
// const redis = require('./Config/redis'); 
// const authRoutes = require('./routes/authRoutes'); 
// const ClientRideRoutes = require('./routes/clientRide.routes');
// const driverRoutes = require ('./routes/auth.Driver.routes'); 
// const DriverRidesRoutes = require('./routes/DriverRides.routes')
// const path = require('path');
// const { createAdapter } = require('@socket.io/redis-adapter');
// const pubClient = redis;
// const subClient = pubClient.duplicate();
// io.adapter(createAdapter(pubClient, subClient));

// // Initialize Express app
// const app = express();
// app.use(passport.initialize());
// app.use(express.static(path.join(__dirname, 'public')));
// app.set('trust proxy', 1)
// // Logger setup
// const logger = winston.createLogger({
//   level: 'info',
//   format: winston.format.combine(
//     winston.format.timestamp(),
//     winston.format.json()
//   ),
//   transports: [
//     new winston.transports.Console(),
//     new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
//     new winston.transports.File({ filename: 'logs/combined.log' })
//   ]
// });

// // Environment validation
// const validateEnv = () => {
//   const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'ENCRYPTION_KEY'];
//   const missingEnv = requiredEnv.filter(key => !process.env[key]);
//   if (missingEnv.length > 0) {
//     logger.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
//     throw new Error('Missing required environment variables');
//   }
//   if (!process.env.REDIS_URL && (!process.env.REDIS_HOST || !process.env.REDIS_PORT)) {
//     logger.error('Redis configuration missing: REDIS_URL or REDIS_HOST and REDIS_PORT required');
//     throw new Error('Redis configuration missing');
//   }
// };
// // Middleware
// app.use(helmet()); // Security headers
// app.use(cors({
//   origin: process.env.CORS_ORIGIN || '*',
//   methods: ['GET', 'POST', 'PUT', 'DELETE'],
//   credentials: true
// }));
// app.use(express.json()); // Parse JSON bodies
// app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies


// // Global rate limiter
// const globalLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // Max 100 requests per IP
//   message: { status: 'error', message: 'Too many requests, please try again later' }
// });
// app.use(globalLimiter);

// // MongoDB connection
// const connectMongoDB = async () => {
//   try {
//     await mongoose.connect(process.env.MONGO_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     logger.info('MongoDB connected successfully', { uri: process.env.MONGO_URI });
//   } catch (error) {
//     logger.error('MongoDB connection error', { error: error.message });
//     process.exit(1);
//   }
// };

// // Routes
// app.use('/auth', authRoutes);// this is for client authentication
// app.use('/clientRide', ClientRideRoutes);
// app.use('/driverAuth', driverRoutes);// DRIVER AUTHENTICATION ROUTES
// app.use('/driverRides', DriverRidesRoutes); // this is for driver ride routes


// const swaggerAuthRoutes = require('./routes/SwaggerGoogleAuth'); // swagger documentation
// app.use('/', swaggerAuthRoutes); 

// // Health check endpoint
// app.get('/health', async (req, res) => {
//   try {
//     await redis.ping(); // Test Redis connection
//     await mongoose.connection.db.admin().ping(); // Test MongoDB connection
//     res.status(200).json({ status: 'success', message: 'Server is healthy' });
//   } catch (error) {
//     logger.error('Health check failed', { error: error.message });
//     res.status(500).json({ status: 'error', message: 'Server is unhealthy' });
//   }
// });

// // Error handling middleware
// app.use((err, req, res, next) => {
//   logger.error('Unexpected error', { error: err.message, stack: err.stack });
//   res.status(500).json({ status: 'error', message: 'An unexpected error occurred' });
// });

// // Start server
// const PORT = process.env.PORT || 3000;
// const startServer = async () => {
//   try {
//     validateEnv();
//     await connectMongoDB();
//     app.listen(PORT, () => {
//       logger.info(`Server running on port ${PORT}`);
//     });
//   } catch (error) {
//     logger.error('Server startup error', { error: error.message });
//     process.exit(1);
//   }
// };
// const setupSwagger = require('./swagger');

// const open = require('open').default;
// setupSwagger(app);
// open("https://sarriride.onrender.com/api-docs");

// startServer();

