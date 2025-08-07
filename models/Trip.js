const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const TripSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: 'Client', required: true },
  category: { type: String, enum: ['luxury', 'comfort', 'xl'], required: true },
  startLocation: {
    latitude: { type: Number, required: true, min: -90, max: 90 },
    longitude: { type: Number, required: true, min: -180, max: 180 }
  },
  endLocation: {
    latitude: { type: Number, required: true, min: -90, max: 90 },
    longitude: { type: Number, required: true, min: -180, max: 180 }
  },
  distanceKm: { type: Number, required: true, min: 0 },
  price: { type: Number, required: true, min: 0 },
  seats: { type: Number, required: true, min: 1, validate: { validator: Number.isInteger } },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

TripSchema.index({ userId: 1 });
TripSchema.index({ createdAt: 1 });

module.exports = mongoose.model('Trip', TripSchema);
