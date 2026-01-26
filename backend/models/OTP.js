const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  otp: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['signup', 'login', 'password_reset'],
    required: true
  },
  verified: {
    type: Boolean,
    default: false
  },
  attempts: {
    type: Number,
    default: 0
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
  }
}, {
  timestamps: true
});

otpSchema.index({ email: 1, type: 1 });

module.exports = mongoose.model('OTP', otpSchema);
