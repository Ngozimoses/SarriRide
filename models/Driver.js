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
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
  },
  FirstName: {
    type: String,
    required: true,
    trim: true,
    minlength: [2, 'First name must be at least 2 characters']
  },
  LastName: {
    type: String,
    required: true,
    trim: true,
    minlength: [2, 'Last name must be at least 2 characters']
  },
  picture: {
    type: String,
    default: '',
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: [8, 'Password must be at least 8 characters']
  },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    sparse: true,
    match: [/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number']
  },
  DateOfBirth: {
    type: Date,
    required: true,
    validate: {
      validator: function (value) {
        return value < new Date();
      },
      message: 'Date of birth must be in the past'
    }
  },
  Gender: {
    type: String,
    enum: ['male', 'female', 'other'],
    required: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  adminVerified: {
    type: Boolean,
    default: false
  },
  resetToken: {
    type: String
  },
  resetTokenExpires: {
    type: Date
  },
  licenseNumber: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: [5, 'License number must be at least 5 characters']
  },
  drivingLicense: {
    issueDate: {
      type: Date,
      required: true,
      validate: {
        validator: function (value) {
          return value < new Date();
        },
        message: 'Issue date must be in the past'
      }
    },
    expiryDate: {
      type: Date,
      required: true,
      validate: {
        validator: function (value) {
          return value > new Date();
        },
        message: 'Expiry date must be in the future'
      }
    },
    frontsideImage: {
      type: String,
      required: true,
      trim: true,
      match: [/^https?:\/\/.*\.(png|jpg|jpeg)$/, 'Please provide a valid image URL for the frontside of the license']
    },
    backsideImage: {
      type: String,
      required: true,
      trim: true,
      match: [/^https?:\/\/.*\.(png|jpg|jpeg)$/, 'Please provide a valid image URL for the backside of the license']
    }
  },
  currentAddress: {
    address: { type: String, required: true, trim: true },
    state: { type: String, required: true, trim: true },
    city: { type: String, required: true, trim: true },
    country: { type: String, required: true, trim: true },
    postalCode: { 
      type: String, 
      required: true, 
      trim: true,
      match: [/^\d{5}(-\d{4})?$|^\d{6}$/, 'Please enter a valid postal code']
    }
  },
  permanentAddress: {
    address: { type: String, required: true, trim: true },
    state: { type: String, required: true, trim: true },
    city: { type: String, required: true, trim: true },
    country: { type: String, required: true, trim: true },
    postalCode: { 
      type: String, 
      required: true, 
      trim: true,
      match: [/^\d{5}(-\d{4})?$|^\d{6}$/, 'Please enter a valid postal code']
    }
  },
  emergencyContactNumber: {
    type: String,
    required: true,
    trim: true,
    match: [/^\+?[1-9]\d{1,14}$/, 'Please enter a valid emergency contact number']
  },
  bankDetails: {
    bankAccountNumber: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      match: [/^\d{10,20}$/, 'Please enter a valid bank account number']
    },
    bankName: {
      type: String,
      required: true,
      trim: true,
      minlength: [2, 'Bank name must be at least 2 characters']
    },
    bankAccountName: {
      type: String,
      required: true,
      trim: true,
      minlength: [2, 'Bank account name must be at least 2 characters']
    }
  },
  vehicleDetails: {
    make: { type: String, required: true, trim: true },
    model: { type: String, required: true, trim: true },
    year: { 
      type: Number, 
      required: true,
      validate: {
        validator: Number.isInteger,
        message: 'Year must be an integer'
      }
    },
    licensePlate: { type: String, required: true, trim: true, unique: true }
  },
  availabilityStatus: {
    type: String,
    enum: ['available', 'unavailable', 'on_trip'],
    default: 'unavailable'
  },
  role: {
    type: String,
    enum: ['driver'],
    default: 'driver',
    immutable: true
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Number
  }
});

// Hash password before saving
driverSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Validate that expiryDate is after issueDate
driverSchema.pre('save', async function (next) {
  if (this.isModified('drivingLicense')) {
    if (this.drivingLicense.expiryDate <= this.drivingLicense.issueDate) {
      return next(new Error('Expiry date must be after issue date'));
    }
  }
  next();
});

// Create indexes for performance
driverSchema.index({ email: 1 }, { unique: true, sparse: true });
driverSchema.index({ phoneNumber: 1 }, { unique: true, sparse: true });
driverSchema.index({ licenseNumber: 1 }, { unique: true });
driverSchema.index({ 'vehicleDetails.licensePlate': 1 }, { unique: true });
driverSchema.index({ 'bankDetails.bankAccountNumber': 1 }, { unique: true, sparse: true });
driverSchema.index({ emergencyContactNumber: 1 }, { sparse: true });

module.exports = mongoose.model('Driver', driverSchema);
