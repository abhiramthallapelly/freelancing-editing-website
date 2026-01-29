const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models-pg/User');
const OTP = require('../models-pg/OTP');
const { OAuth2Client } = require('google-auth-library');
const { validateRegister, validateLogin } = require('../middleware/validator');
const { authLimiter } = require('../middleware/rateLimiter');
const { sendEmail } = require('../utils/email');
const router = express.Router();

const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

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

router.post('/register', validateRegister, async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;

    if (!username || !email || !password || !fullName) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    const existingUser = await User.findOne({ 
      $or: [{ username }, { email: email.toLowerCase() }] 
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      full_name: fullName,
      auth_provider: 'local'
    });

    const token = jwt.sign(
      { userId: user.id.toString(), username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    const { sendWelcomeEmail } = require('../utils/email');
    sendWelcomeEmail(user.email, fullName || username).catch(err => {
      console.error('Error sending welcome email:', err);
    });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user.id.toString(),
        username: user.username,
        email: user.email,
        fullName: user.full_name
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Username or email already exists' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

router.post('/login', validateLogin, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    const user = await User.findOne({ 
      $or: [{ username }, { email: username.toLowerCase() }] 
    });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.password) {
      return res.status(401).json({ message: 'Please sign in with your social account' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Update last login
    await User.updateLastLogin(user.id);

    const token = jwt.sign(
      { userId: user.id.toString(), username: user.username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id.toString(),
        username: user.username,
        email: user.email,
        fullName: user.full_name
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      user: {
        id: user.id.toString(),
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { fullName, email } = req.body;

    if (!fullName || !email) {
      return res.status(400).json({ message: 'Full name and email are required' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { full_name: fullName, email: email.toLowerCase() }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Profile update error:', error);
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Email already in use' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

router.put('/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'New password must be at least 6 characters long' });
    }

    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.password) {
      return res.status(400).json({ message: 'OAuth users cannot change password. Please use your social account to sign in.' });
    }

    const isValidPassword = await bcrypt.compare(currentPassword, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await User.findByIdAndUpdate(user.id, { password: hashedPassword });

    res.json({ message: 'Password changed successfully' });

  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

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

    res.json({ success: true, authUrl, configured: true });
  } catch (error) {
    console.error('Google OAuth URL generation error:', error);
    res.status(500).json({ success: false, message: 'Error generating Google OAuth URL', error: error.message });
  }
});

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

router.get('/google/callback', async (req, res) => {
  try {
    if (!googleClient || !process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_not_configured`);
    }

    const { code } = req.query;

    if (!code) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_failed`);
    }

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

    let existingUser = await User.findOne({ 
      $or: [{ email }, { google_id: googleId }] 
    });

    if (existingUser) {
      if (!existingUser.google_id) {
        await User.findByIdAndUpdate(existingUser.id, {
          google_id: googleId,
          auth_provider: 'google',
          profile_picture: profilePicture || existingUser.profile_picture
        });
      }
      
      await User.updateLastLogin(existingUser.id);
      
      const token = jwt.sign(
        { userId: existingUser.id.toString(), email: existingUser.email, authProvider: 'google' },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '7d' }
      );

      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?token=${token}&email=${encodeURIComponent(existingUser.email)}&name=${encodeURIComponent(existingUser.full_name || existingUser.username || existingUser.email)}`);
    } else {
      const username = email.split('@')[0];
      const newUser = await User.create({
        email,
        username,
        full_name: fullName || username,
        auth_provider: 'google',
        google_id: googleId,
        profile_picture: profilePicture || null,
        is_verified: true
      });
      
      await User.updateLastLogin(newUser.id);
      
      const token = jwt.sign(
        { userId: newUser.id.toString(), email, authProvider: 'google' },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '7d' }
      );

      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?token=${token}&email=${encodeURIComponent(email)}&name=${encodeURIComponent(fullName || username)}`);
    }

  } catch (error) {
    console.error('Google OAuth callback error:', error);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html?error=oauth_error`);
  }
});

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

router.post('/send-otp', async (req, res) => {
  try {
    const { email, type } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    const validTypes = ['signup', 'login', 'password_reset'];
    const otpType = validTypes.includes(type) ? type : 'signup';
    
    const recentOTPsCount = await OTP.countDocuments({
      email: email.toLowerCase(),
      created_at: { $gte: new Date(Date.now() - 10 * 60 * 1000) }
    });
    
    if (recentOTPsCount >= 3) {
      return res.status(429).json({ message: 'Too many OTP requests. Please wait 10 minutes before trying again.' });
    }
    
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    await OTP.delete({ email: email.toLowerCase(), type: otpType });
    
    await OTP.create({
      email: email.toLowerCase(),
      otp,
      type: otpType,
      expiresAt
    });
    
    const emailSent = await sendOTPEmail(email, otp, otpType);
    
    if (!emailSent) {
      return res.status(500).json({ message: 'Failed to send verification email' });
    }
    
    res.json({ message: 'Verification code sent to your email', email: email.toLowerCase() });
    
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ message: 'Failed to send verification code' });
  }
});

router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp, type } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and verification code are required' });
    }
    
    const otpType = type || 'signup';
    
    const otpRecord = await OTP.findOne({
      email: email.toLowerCase(),
      type: otpType,
      expires_at: { $gt: new Date() }
    });
    
    if (!otpRecord) {
      return res.status(400).json({ message: 'Verification code expired or not found. Please request a new code.' });
    }
    
    if (otpRecord.attempts >= 5) {
      await OTP.deleteOne({ id: otpRecord.id });
      return res.status(400).json({ message: 'Too many failed attempts. Please request a new code.' });
    }
    
    if (otpRecord.otp !== otp) {
      otpRecord.attempts = (otpRecord.attempts || 0) + 1;
      await OTP.save(otpRecord);
      return res.status(400).json({ message: 'Invalid verification code' });
    }
    
    otpRecord.verified = true;
    await OTP.save(otpRecord);
    
    res.json({ message: 'Email verified successfully', verified: true });
    
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ message: 'Failed to verify code' });
  }
});

router.post('/register-with-otp', validateRegister, async (req, res) => {
  try {
    const { username, email, password, fullName, otp } = req.body;

    if (!otp) {
      return res.status(400).json({ message: 'Verification code is required' });
    }

    const otpRecord = await OTP.findOne({
      email: email.toLowerCase(),
      type: 'signup',
      verified: true,
      expires_at: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Please verify your email first' });
    }

    const existingUser = await User.findOne({ 
      $or: [{ username }, { email: email.toLowerCase() }] 
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      full_name: fullName,
      auth_provider: 'local',
      is_verified: true
    });

    await OTP.deleteOne({ id: otpRecord.id });

    const token = jwt.sign(
      { userId: user.id.toString(), username, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    const { sendWelcomeEmail } = require('../utils/email');
    sendWelcomeEmail(user.email, fullName || username).catch(err => {
      console.error('Error sending welcome email:', err);
    });

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user.id.toString(),
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

router.post('/login-with-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and verification code are required' });
    }

    const otpRecord = await OTP.findOne({
      email: email.toLowerCase(),
      type: 'login',
      expires_at: { $gt: new Date() }
    });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Verification code expired. Please request a new code.' });
    }

    if (otpRecord.attempts >= 5) {
      await OTP.deleteOne({ id: otpRecord.id });
      return res.status(400).json({ message: 'Too many failed attempts. Please request a new code.' });
    }

    if (otpRecord.otp !== otp) {
      otpRecord.attempts = (otpRecord.attempts || 0) + 1;
      await OTP.save(otpRecord);
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    let user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      const username = email.split('@')[0];
      user = await User.create({
        email: email.toLowerCase(),
        username,
        auth_provider: 'local',
        is_verified: true
      });
    }

    await OTP.deleteOne({ id: otpRecord.id });
    await User.updateLastLogin(user.id);

    const token = jwt.sign(
      { userId: user.id.toString(), email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id.toString(),
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

router.get('/status', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.json({ authenticated: false, message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', async (err, decoded) => {
    if (err) {
      return res.json({ authenticated: false, message: 'Invalid or expired token' });
    }

    try {
      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.json({ authenticated: false, message: 'User not found' });
      }

      res.json({
        authenticated: true,
        user: {
          id: user.id.toString(),
          username: user.username,
          email: user.email,
          fullName: user.full_name
        }
      });
    } catch (error) {
      res.json({ authenticated: false, message: 'Error verifying user' });
    }
  });
});

module.exports = router;
