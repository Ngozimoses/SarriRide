const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const adminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Invalid email format'],
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false,
  },
  FirstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
  },
  LastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
  },
  role: {
    type: String,
    enum: ['admin'],
    default: 'admin',
    immutable: true,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
    select: false,
  },
  lockUntil: {
    type: Number,
    select: false,
  },
  resetToken: {
    type: String,
    select: false,
  },
  resetTokenId: {
    type: String,
    select: false,
  },
  resetTokenSalt: {
    type: String,
    select: false,
  },
  resetTokenExpires: {
    type: Number,
    select: false,
  },
}, {
  timestamps: true,
});

// Indexes for efficient queries
adminSchema.index({ email: 1 });
adminSchema.index({ resetTokenId: 1 }, { sparse: true });

// Pre-save hook to hash password
adminSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Method to compare passwords
adminSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('Admin', adminSchema);
