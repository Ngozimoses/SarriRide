const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PricingSchema = new Schema({
  category: {
    type: String,
    enum: ['luxury', 'comfort', 'xl'],
    required: true,
    unique: true,
  },
  baseFee: {
    type: Number,
    required: true,
    min: 0,
  },
  perKm: {
    type: Number,
    required: true,
    min: 0,
  },
  minimumFare: {
    type: Number,
    required: true,
    min: 0,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('Pricing', PricingSchema);
