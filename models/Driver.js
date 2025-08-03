const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const driverSchema = new mongoose.Schema({
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
    required: true,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  adminVerified: {
    type: Boolean,
    default: false,
  },
  resetToken: {
    type: String,
  },
  resetTokenExpires: {
    type: Date,
  },
  licenseNumber: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  vehicleDetails: {
    make: { type: String, required: true, trim: true },
    model: { type: String, required: true, trim: true },
    year: { type: Number, required: true },
    licensePlate: { type: String, required: true, trim: true, unique: true },
  },
  availabilityStatus: {
    type: String,
    enum: ['available', 'unavailable', 'on_trip'],
    default: 'unavailable',
  },
  role: {
    type: String,
    enum: ['driver'],
    default: 'driver',
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
driverSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Create indexes for performance
driverSchema.index({ email: 1 }, { unique: true });
driverSchema.index({ licenseNumber: 1 }, { unique: true });
driverSchema.index({ 'vehicleDetails.licensePlate': 1 }, { unique: true });

module.exports = mongoose.model('Driver', driverSchema);
