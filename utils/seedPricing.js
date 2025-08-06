const mongoose = require('mongoose');
const Pricing = require('../models/PricingSchema');

async function seedPricing() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    await Pricing.deleteMany({});
    await Pricing.insertMany([
      { category: 'luxury', baseFee: 500, perKm: 3000, minimumFare: 1500 },
      { category: 'comfort', baseFee: 500, perKm: 2000, minimumFare: 1500 },
      { category: 'xl', baseFee: 500, perKm: 2400, minimumFare: 1500 },
    ]);
    console.log('Pricing seeded');
  } catch (error) {
    console.error('Seeding error:', error.message);
  } finally {
    mongoose.disconnect();
  }
}

seedPricing();
