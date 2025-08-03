require('dotenv').config();
const crypto = require('crypto');
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

const algorithm = 'aes-256-cbc';
const keys = [
  Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
  Buffer.from(process.env.ENCRYPTION_KEY_PREVIOUS || '0'.repeat(64), 'hex'),
];

if (keys[0].length !== 32) {
  logger.error('Invalid COOKIE_ENCRYPTION_KEY: must be a 32-byte key (64 hex characters)');
  throw new Error('Invalid COOKIE_ENCRYPTION_KEY: must be a 32-byte key (64 hex characters)');
}

function encrypt(text) {
  if (typeof text !== 'string' || !text) {
    logger.error('Invalid input for encryption', { type: typeof text });
    throw new Error('Input must be a non-empty string');
  }
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, keys[0], iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
  } catch (error) {
    logger.error('Encryption error', { error: error.message, textLength: text.length });
    throw new Error('Failed to encrypt data');
  }
}

function decrypt(encrypted) {
  try {
    const [ivHex, encryptedText] = encrypted.split(':');
    if (!ivHex || !encryptedText) {
      logger.error('Invalid encrypted data format', { encrypted });
      throw new Error('Invalid encrypted data format');
    }
    const iv = Buffer.from(ivHex, 'hex');
    if (iv.length !== 16) {
      logger.error('Invalid IV length', { ivHex });
      throw new Error('Invalid IV length');
    }

    let lastError = null;
    for (const key of keys) {
      try {
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
      } catch (error) {
        lastError = error;
      }
    }
    logger.error('Decryption error', { error: lastError.message, encrypted });
    throw new Error('Failed to decrypt token');
  } catch (error) {
    logger.error('Decryption error', { error: error.message, encrypted });
    throw new Error('Failed to decrypt token');
  }
}

module.exports = { encrypt, decrypt };
