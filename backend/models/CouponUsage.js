const mongoose = require('mongoose');

const couponUsageSchema = new mongoose.Schema({
  coupon_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Coupon',
    required: true
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  purchase_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Purchase'
  },
  discount_amount: {
    type: Number,
    required: true,
    min: 0
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

module.exports = mongoose.model('CouponUsage', couponUsageSchema);

