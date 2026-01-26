const { body, param, query, validationResult } = require('express-validator');

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

// User registration validation
const validateRegister = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('fullName')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters'),
  handleValidationErrors
];

// User login validation
const validateLogin = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username or email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

// Project upload validation
const validateProjectUpload = [
  body('title')
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Title must be between 3 and 200 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Description must be less than 1000 characters'),
  body('price')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Price must be a non-negative integer'),
  body('is_free')
    .optional()
    .isIn(['0', '1', 0, 1, true, false])
    .withMessage('is_free must be 0 or 1'),
  handleValidationErrors
];

// ID parameter validation
const validateId = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('ID must be a positive integer'),
  handleValidationErrors
];

// Review validation
const validateReview = [
  body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Name is required'),
  body('email')
    .optional()
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('message')
    .trim()
    .isLength({ min: 1, max: 2000 })
    .withMessage('Message is required'),
  body('rating')
    .isInt({ min: 1, max: 5 })
    .withMessage('Rating must be between 1 and 5'),
  handleValidationErrors
];

// Contact form validation
const validateContact = [
  body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Name is required and must be less than 100 characters'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('message')
    .trim()
    .isLength({ min: 1, max: 5000 })
    .withMessage('Message is required'),
  body('subject')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Subject must be less than 200 characters'),
  handleValidationErrors
];

// Coupon validation
const validateCoupon = [
  body('code')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Coupon code must be between 3 and 50 characters')
    .matches(/^[A-Z0-9_-]+$/)
    .withMessage('Coupon code can only contain uppercase letters, numbers, hyphens, and underscores'),
  body('discount_value')
    .isInt({ min: 1 })
    .withMessage('Discount value must be a positive integer'),
  body('discount_type')
    .optional()
    .isIn(['percentage', 'fixed'])
    .withMessage('Discount type must be percentage or fixed'),
  handleValidationErrors
];

// Search query validation
const validateSearch = [
  query('search')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Search term must be less than 100 characters'),
  query('category')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Category must be less than 50 characters'),
  query('minPrice')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Minimum price must be a non-negative integer'),
  query('maxPrice')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Maximum price must be a non-negative integer'),
  handleValidationErrors
];

module.exports = {
  validateRegister,
  validateLogin,
  validateProjectUpload,
  validateId,
  validateReview,
  validateContact,
  validateCoupon,
  validateSearch,
  handleValidationErrors
};

