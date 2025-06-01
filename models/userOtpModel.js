const mongoose = require('mongoose');

const userOTPSchema = new mongoose.Schema({
  phoneNumber: { type: String, required: true },
  otp: { type: String, required: true },
  expiry: { type: Date, required: true },  
}, { timestamps: true });

module.exports = mongoose.model('UserOTP', userOTPSchema);
