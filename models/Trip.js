/**THIS MODEL TRACKS ALL TRIP RELATED DATA STARTING FROM BOOKING RIDE BY THE CLIENT AND DRIVER ACCEPTING RIDES
 * TO WHEN THE TRIP STARTS AND WHEN IT ENDED , IT ALSO TRACK WHEN USER CANCEL A RIDE AS WELL.
  */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const TripSchema = new Schema({
  clientId: { type: Schema.Types.ObjectId, ref: 'Client', required: true }, 
  driverId: { type: Schema.Types.ObjectId, ref: 'Driver', required: false },
  category: { type: String, enum: ['luxury', 'comfort', 'xl'], required: true },
  requestedPickup: { // Requested pickup location at booking
    latitude: { type: Number, required: true, min: -90, max: 90 },
    longitude: { type: Number, required: true, min: -180, max: 180 }
  },
  requestedDropoff: { // Requested drop-off location at booking
    latitude: { type: Number, required: true, min: -90, max: 90 },
    longitude: { type: Number, required: true, min: -180, max: 180 }
  },
  startLocation: { // Actual start location, optional until trip begins
    latitude: { type: Number, min: -90, max: 90 },
    longitude: { type: Number, min: -180, max: 180 }
  },
  endLocation: { // Actual end location, optional until trip ends
    latitude: { type: Number, min: -90, max: 90 },
    longitude: { type: Number, min: -180, max: 180 }
  },
  distanceKm: { type: Number, required: true, min: 0 }, // Initially based on requested locations
  price: { type: Number, required: true, min: 0 },
  seats: { type: Number, required: true, min: 1, validate: { validator: Number.isInteger } },
  status: { 
    type: String, 
    enum: ['pending', 'accepted', 'in_progress', 'completed', 'cancelled'], 
    default: 'pending', 
    required: true 
  }, // Added for lifecycle
  bookedAt: { type: Date, default: Date.now }, // Tracks booking time
  acceptedAt: { type: Date }, // Tracks when driver accepts
  startedAt: { type: Date }, // Tracks when trip begins
  completedAt: { type: Date }, // Tracks when trip ends
  cancelledAt: { type: Date }, // Tracks when cancelled
  updatedAt: { type: Date, default: Date.now, onUpdate: Date.now }
});

// Indexes
TripSchema.index({ clientId: 1 });
TripSchema.index({ driverId: 1 });
TripSchema.index({ status: 1 });
TripSchema.index({ bookedAt: 1 });
TripSchema.index({ acceptedAt: 1 });

module.exports = mongoose.model('Trip', TripSchema);





// const mongoose = require('mongoose');
// const Schema = mongoose.Schema;

// const TripSchema = new Schema({
//   userId: { type: Schema.Types.ObjectId, ref: 'Client', required: true },
//   category: { type: String, enum: ['luxury', 'comfort', 'xl'], required: true },
//   startLocation: {
//     latitude: { type: Number, required: true, min: -90, max: 90 },
//     longitude: { type: Number, required: true, min: -180, max: 180 }
//   },
//   endLocation: {
//     latitude: { type: Number, required: true, min: -90, max: 90 },
//     longitude: { type: Number, required: true, min: -180, max: 180 }
//   },
//   distanceKm: { type: Number, required: true, min: 0 },
//   price: { type: Number, required: true, min: 0 },
//   seats: { type: Number, required: true, min: 1, validate: { validator: Number.isInteger } },
//   createdAt: { type: Date, default: Date.now },
//   updatedAt: { type: Date, default: Date.now }
// });

// TripSchema.index({ userId: 1 });
// TripSchema.index({ createdAt: 1 });

// module.exports = mongoose.model('Trip', TripSchema);
