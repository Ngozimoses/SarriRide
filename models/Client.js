const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const findOrCreate = require('mongoose-findorcreate');

const clientSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    sparse: true,
  },
  FirstName: {
    type: String,
    required: true,
    trim: true,
  },
  LastName: {
    type: String,
    required: true,
    trim: true,
  },
  picture: {
    type: String,
    default: '',
  },
  password: {
    type: String,
    required: function () {
      return !this.googleId && !this.facebookId; // Password required if no third-party ID
    },
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true,
  },
  facebookId: {
    type: String,
    unique: true,
    sparse: true,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  resetToken: {
    type: String,
  },
  resetTokenSalt: {
    type: String,
  },
  resetTokenId: {
    type: String,
  },
  resetTokenExpires: {
    type: Date,
  },
  role: {
    type: String,
    enum: ['client'],
    default: 'client',
    immutable: true,
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
  },
  lockUntil: {
    type: Number,
  },
});

// Hash password before saving
clientSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  if (this.password) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Create indexes for performance
clientSchema.index({ email: 1 }, { unique: true });
clientSchema.index({ googleId: 1 }, { unique: true, sparse: true });
clientSchema.index({ facebookId: 1 }, { unique: true, sparse: true });

clientSchema.plugin(findOrCreate);

module.exports = mongoose.model('Client', clientSchema);
