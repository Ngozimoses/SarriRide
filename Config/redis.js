require('dotenv').config();
const Redis = require('ioredis');
const winston = require('winston');

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

const validateEnv = () => {
  if (!process.env.REDIS_URL && (!process.env.REDIS_HOST || !process.env.REDIS_PORT)) {
    logger.error('Redis configuration missing: REDIS_URL or REDIS_HOST and REDIS_PORT required');
    throw new Error('Redis configuration missing');
  }
  if (process.env.REDIS_TLS === 'true' && !process.env.REDIS_PASSWORD) {
    logger.warn('Redis TLS enabled but no password provided');
  }
};

const redisConfig = process.env.REDIS_URL
  ? { uri: process.env.REDIS_URL }
  : {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT) || 6379,
      password: process.env.REDIS_PASSWORD || undefined,
      db: parseInt(process.env.REDIS_DB) || 0,
      tls: process.env.REDIS_TLS === 'true' ? {} : undefined,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000); // Exponential backoff, max 2s
        logger.warn(`Redis reconnect attempt ${times}, retrying in ${delay}ms`);
        return delay;
      },
      maxRetriesPerRequest: 10,
      connectTimeout: 10000, // 10s timeout
      commandTimeout: 5000, // 5s per command
    };

const redis = new Redis(process.env.REDIS_URL || redisConfig);

redis.on('connect', () => {
  logger.info('Redis connected successfully', {
    host: redis.options.host,
    port: redis.options.port,
    db: redis.options.db,
  });
});

redis.on('ready', () => {
  logger.info('Redis client ready');
});

redis.on('error', (error) => {
  logger.error('Redis connection error', { error: error.message });
});

redis.on('close', () => {
  logger.warn('Redis connection closed');
});

redis.on('reconnecting', () => {
  logger.info('Redis reconnecting');
});

validateEnv();

module.exports = redis;
