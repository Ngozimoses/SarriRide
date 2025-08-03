const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'userModel',
    required: true,
  },
  userModel: {
    type: String,
    required: true,
    enum: ['Client', 'Driver', 'Admin', 'Rider'],
  },
  token: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  userAgent: {
    type: String,
    default: 'unknown',
  },
  ipAddress: {
    type: String,
    default: 'unknown',
  },
  revoked: {
    type: Boolean,
    default: false,
  },
  revokedAt: {
    type: Date,
  },
  replacedByTokenId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'RefreshToken',
  },
});

RefreshTokenSchema.index({ token: 1 });
RefreshTokenSchema.index({ userId: 1, userModel: 1, revoked: 1, expiresAt: 1 });

module.exports = mongoose.model('RefreshToken', RefreshTokenSchema);
