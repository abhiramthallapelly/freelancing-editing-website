const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const OTP = require('../models/OTP');
const { OAuth2Client } = require('google-auth-library');
const { validateRegister, validateLogin } = require('../middleware/validator');
const { authLimiter } = require('../middleware/rateLimiter');
const { sendEmail } = require('../utils/email');
const router = express.Router();

// Generate 6-digit OTP
const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Send OTP email
const sendOTPEmail = async (email, otp, type) => {
  const subject = type === 'signup' 
    ? 'Verify Your Email - ABHIRAM CREATIONS' 
    : 'Login Verification Code - ABHIRAM CREATIONS';
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #00bfa6; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .otp-box { background: #00bfa6; color: white; font-size: 32px; font-weight: bold; padding: 20px; text-align: center; letter-spacing: 8px; border-radius: 10px; margin: 20px 0; }
        .warning { color: #e74c3c; font-size: 12px; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>ABHIRAM CREATIONS</h1>
        </div>
        <div class="content">
          <p>Hello,</p>
          <p>${type === 'signup' ? 'Thank you for signing up! Please use the verification code below to complete your registration:' : 'Use the verification code below to complete your login:'}</p>
          <div class="otp-box">${otp}</div>
          <p>This code will expire in <strong>10 minutes</strong>.</p>
          <p class="warning">If you did not request this code, please ignore this email.</p>
          <p>Best regards,<br>ABHIRAM CREATIONS Team</p>
        </div>
      </div>
    </body>
    </html>
  `;
  
  return await sendEmail(email, subject, html);
};

// Initialize Google OAuth Client (only if credentials are provided)
let googleClient = null;
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  googleClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3001/api/auth/google/callback'
  );
  console.log('Google OAuth initialized successfully');
} else {
  console.warn('Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable Google Sign-In.');
}

// User Registration
router.post('/register', validateRegister, async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;

    // Validation
    if (!username || !email || !password || !fullName) {
      return res.status(400).json({ 
        message: 'All fields are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email: email.toLowerCase() }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        message: 'Username or email already exists' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      full_name: fullName,
      auth_provider: 'local'
    });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id.toString(), username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Send welcome email
    const { sendWelcomeEmail } = require('../utils/email');
    sendWelcomeEmail(user.email, fullName || username).catch(err => {
      console.error('Error sending welcome email:', err);
    });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        fullName: user.full_name
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === 11000) { // MongoDB duplicate key error
      return res.status(400).json({ 
        message: 'Username or email already exists' 
      });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// User Login
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ 
        message: 'Username and password are required' 
      });
    }

    // Find user
    const user = await User.findOne({ 
      $or: [{ username }, { email: username.toLowerCase() }] 
    });

    if (!user) {
      return res.status(401).json({ 
        message: 'Invalid credentials' 
      });
    }

    // Check if user has a password (OAuth users might not)
    if (!user.password) {
      return res.status(401).json({ 
        message: 'Please sign in with your social account' 
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        message: 'Invalid credentials' 
      });
    }

    // Update last login
    user.last_login = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        fullName: user.full_name
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get current user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('username email full_name createdAt')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        created_at: user.createdAt
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { fullName, email } = req.body;

    if (!fullName || !email) {
      return res.status(400).json({ 
        message: 'Full name and email are required' 
      });
    }

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { full_name: fullName, email: email.toLowerCase() },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Profile update error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Email already in use' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Change password
router.put('/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        message: 'Current and new password are required' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        message: 'New password must be at least 6 characters long' 
      });
    }

    // Get current user
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.password) {
      return res.status(400).json({ 
        message: 'OAuth users cannot change password. Please use your social account to sign in.' 
      });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        message: 'Current password is incorrect' 
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Password changed successfully' });

  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Google OAuth - Get authentication URL
router.get('/google', (req, res) => {
  try {
    if (!googleClient || !process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.status(503).json({ 
        success: false,
        message: 'Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your environment variables.',
        configured: false
      });
    }

    const scopes = [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ];

    const authUrl = googleClient.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      prompt: 'consent'
    });

    res.json({ 
      success: true,
      authUrl,
      configured: true
    });
  } catch (error) {
    console.error('Google OAuth URL generation error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error generating Google OAuth URL',
      error: error.message
    });
  }
});

// Check Google OAuth configuration status
router.get('/google/status', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3001/api/auth/google/callback';
  
  const isConfigured = !!(clientId && clientSecret);
  const isValidClientId = clientId && clientId.includes('.apps.googleusercontent.com');
  
  res.json({
    configured: isConfigured,
    hasClientId: !!clientId,
    hasClientSecret: !!clientSecret,
    isValidClientId: isValidClientId,
    redirectUri: redirectUri,
    clientIdFormat: clientId ? (isValidClientId ? 'valid' : 'invalid - should end with .apps.googleusercontent.com') : 'not set',
    message: !isConfigured 
      ? 'Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in environment variables.'
      : !isValidClientId
      ? 'Client ID format appears invalid. Should end with .apps.googleusercontent.com'
      : 'Google OAuth is configured correctly. Make sure redirect URI matches Google Cloud Console.'
  });
});

// Google OAuth - Callback handler
router.get('/google/callback', async (req, res) => {
  try {
    if (!googleClient || !process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_not_configured`);
    }

    const { code } = req.query;

    if (!code) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_failed`);
    }

    // Exchange code for tokens
    let tokens;
    try {
      const tokenResponse = await googleClient.getToken(code);
      tokens = tokenResponse.tokens;
      googleClient.setCredentials(tokens);
    } catch (tokenError) {
      console.error('Error exchanging code for tokens:', tokenError.message);
      if (tokenError.message.includes('invalid_client')) {
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_invalid_client`);
      }
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_token_exchange_failed`);
    }

    // Get user info from Google using ID token
    if (!tokens.id_token) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_failed`);
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email.toLowerCase();
    const fullName = payload.name;
    const profilePicture = payload.picture;

    if (!email) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=no_email`);
    }

    // Check if user exists
    let existingUser = await User.findOne({ 
      $or: [{ email }, { google_id: googleId }] 
    });

    if (existingUser) {
      // Update existing user with Google info if needed
      if (!existingUser.google_id) {
        existingUser.google_id = googleId;
        existingUser.auth_provider = 'google';
        if (profilePicture) existingUser.profile_picture = profilePicture;
        await existingUser.save();
      } else if (profilePicture && !existingUser.profile_picture) {
        existingUser.profile_picture = profilePicture;
        await existingUser.save();
      }
      
      // Update last login
      existingUser.last_login = new Date();
      await existingUser.save();
      
      // Generate JWT token for existing user
      const token = jwt.sign(
        { userId: existingUser._id.toString(), email: existingUser.email, authProvider: 'google' },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '7d' }
      );

      // Redirect to frontend with token
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?token=${token}&email=${encodeURIComponent(existingUser.email)}&name=${encodeURIComponent(existingUser.full_name || existingUser.username || existingUser.email)}`);
    } else {
      // Create new user
      const username = email.split('@')[0]; // Use email prefix as username
      const newUser = await User.create({
        email,
        username,
        full_name: fullName || username,
        auth_provider: 'google',
        google_id: googleId,
        profile_picture: profilePicture || null,
        is_verified: true,
        last_login: new Date()
      });
      
      // Generate JWT token
      const token = jwt.sign(
        { userId: newUser._id.toString(), email, authProvider: 'google' },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '7d' }
      );

      // Redirect to frontend with token
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?token=${token}&email=${encodeURIComponent(email)}&name=${encodeURIComponent(fullName || username)}`);
    }

  } catch (error) {
    console.error('Google OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_error`);
  }
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Send OTP for email verification
router.post('/send-otp', async (req, res) => {
  try {
    const { email, type } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    const validTypes = ['signup', 'login', 'password_reset'];
    const otpType = validTypes.includes(type) ? type : 'signup';
    
    // Check rate limit - max 3 OTPs per email per 10 minutes
    const recentOTPs = await OTP.countDocuments({
      email: email.toLowerCase(),
      createdAt: { $gte: new Date(Date.now() - 10 * 60 * 1000) }
    });
    
    if (recentOTPs >= 3) {
      return res.status(429).json({ 
        message: 'Too many OTP requests. Please wait 10 minutes before trying again.' 
      });
    }
    
    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    // Delete any existing OTPs for this email and type
    await OTP.deleteMany({ email: email.toLowerCase(), type: otpType });
    
    // Save new OTP
    await OTP.create({
      email: email.toLowerCase(),
      otp,
      type: otpType,
      expiresAt
    });
    
    // Send OTP email
    const emailSent = await sendOTPEmail(email, otp, otpType);
    
    if (!emailSent) {
      return res.status(500).json({ message: 'Failed to send verification email' });
    }
    
    res.json({ 
      message: 'Verification code sent to your email',
      email: email.toLowerCase()
    });
    
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ message: 'Failed to send verification code' });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp, type } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and verification code are required' });
    }
    
    const otpType = type || 'signup';
    
    // Find the OTP record
    const otpRecord = await OTP.findOne({
      email: email.toLowerCase(),
      type: otpType,
      expiresAt: { $gt: new Date() }
    });
    
    if (!otpRecord) {
      return res.status(400).json({ message: 'Verification code expired or not found. Please request a new code.' });
    }
    
    // Check max attempts
    if (otpRecord.attempts >= 5) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ message: 'Too many failed attempts. Please request a new code.' });
    }
    
    // Verify OTP
    if (otpRecord.otp !== otp) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ message: 'Invalid verification code' });
    }
    
    // Mark as verified
    otpRecord.verified = true;
    await otpRecord.save();
    
    res.json({ 
      message: 'Email verified successfully',
      verified: true 
    });
    
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ message: 'Failed to verify code' });
  }
});

// Register with OTP verification
router.post('/register-with-otp', validateRegister, async (req, res) => {
  try {
    const { username, email, password, fullName, otp } = req.body;

    if (!otp) {
      return res.status(400).json({ message: 'Verification code is required' });
    }

    // Verify OTP first
    const otpRecord = await OTP.findOne({
      email: email.toLowerCase(),
      type: 'signup',
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Please verify your email first' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email: email.toLowerCase() }] 
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user with verified email
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      full_name: fullName,
      auth_provider: 'local',
      email_verified: true
    });

    // Delete used OTP
    await OTP.deleteOne({ _id: otpRecord._id });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id.toString(), username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Send welcome email
    const { sendWelcomeEmail } = require('../utils/email');
    sendWelcomeEmail(user.email, fullName || username).catch(err => {
      console.error('Error sending welcome email:', err);
    });

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        fullName: user.full_name
      }
    });

  } catch (error) {
    console.error('Registration with OTP error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login with OTP verification
router.post('/login-with-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and verification code are required' });
    }

    // Verify OTP
    const otpRecord = await OTP.findOne({
      email: email.toLowerCase(),
      type: 'login',
      expiresAt: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Verification code expired. Please request a new code.' });
    }

    if (otpRecord.attempts >= 5) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ message: 'Too many failed attempts. Please request a new code.' });
    }

    if (otpRecord.otp !== otp) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    // Delete used OTP
    await OTP.deleteOne({ _id: otpRecord._id });

    // Update last login
    user.last_login = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        fullName: user.full_name
      }
    });

  } catch (error) {
    console.error('Login with OTP error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
