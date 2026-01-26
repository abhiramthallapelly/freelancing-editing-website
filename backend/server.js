require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');

const logger = require('./utils/logger');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const { connectionErrorHandler, timeoutHandler } = require('./middleware/connectionHandler');
const { apiLimiter, authLimiter, storeLimiter } = require('./middleware/rateLimiter');

const { connectDB } = require('./config/mongodb');
const { initEmailTransporter } = require('./utils/email');
const Category = require('./models/Category');

// Routes
const adminRoutes = require('./routes/admin');
const publicRoutes = require('./routes/public');
const authRoutes = require('./routes/auth');
const oauthRoutes = require('./routes/oauth');
const storeRoutes = require('./routes/store');
const analyticsRoutes = require('./routes/analytics');
const wishlistRoutes = require('./routes/wishlist');
const newsletterRoutes = require('./routes/newsletter');
const couponsRoutes = require('./routes/coupons');
const userRoutes = require('./routes/user');
const backupRoutes = require('./routes/backup');
const paymentsRoutes = require('./routes/payments');
const couponUsageRoutes = require('./routes/couponUsage');

const app = express();

// Trust proxy for Replit environment (needed for rate limiting and secure cookies)
app.set('trust proxy', 1);

/**
 * 🔑 Default development port. Use 5000 for Replit.
 * ❌ Never hardcode ports in production; use env vars for deployments.
 */
const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0';

/* =======================
   MIDDLEWARE
======================= */

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(compression());

app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

app.use(cors({
  origin: (_origin, cb) => cb(null, true),
  credentials: true
}));

app.use(timeoutHandler(30000));

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

app.use(connectionErrorHandler);

/* =======================
   STATIC FILES
======================= */

// Add cache control for development
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '..')));

/* =======================
   ROUTES
======================= */

const authLimiterMiddleware =
  process.env.NODE_ENV === 'production' ? authLimiter : (req, res, next) => next();

app.use('/api/admin', adminRoutes);
app.use('/api/public', apiLimiter, publicRoutes);
app.use('/api/auth', authLimiterMiddleware, authRoutes);
app.use('/api/auth', authLimiterMiddleware, oauthRoutes);
app.use('/api/store', storeLimiter, storeRoutes);
app.use('/api/analytics', apiLimiter, analyticsRoutes);
app.use('/api/wishlist', apiLimiter, wishlistRoutes);
app.use('/api/newsletter', apiLimiter, newsletterRoutes);
app.use('/api/coupons', apiLimiter, couponsRoutes);
app.use('/api/coupon-usage', apiLimiter, couponUsageRoutes);
app.use('/api/user', apiLimiter, userRoutes);
app.use('/api/backup', apiLimiter, backupRoutes);
app.use('/api/payments', apiLimiter, paymentsRoutes);

/* =======================
   HEALTH CHECK
======================= */

app.get('/api/health', async (req, res) => {
  const mongoose = require('mongoose');
  res.json({
    status: 'ok',
    env: process.env.NODE_ENV || 'development',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: process.uptime()
  });
});

/* =======================
   ROOT - Serve frontend
======================= */

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

/* =======================
   ERROR HANDLERS
======================= */

app.use(notFound);
app.use(errorHandler);

/* =======================
   SERVER START
======================= */

async function startServer() {
  // Start server first, then connect to MongoDB in background
  const server = app.listen(PORT, HOST, () => {
    console.log(`🚀 Server LIVE on ${HOST}:${PORT}`);
    initEmailTransporter();
  });

  server.on('error', err => {
    console.error('SERVER ERROR:', err.message);
  });

  // Connect to MongoDB in background (non-blocking)
  (async () => {
    try {
      console.log('🔄 Connecting to MongoDB...');
      await connectDB();
      console.log('✅ MongoDB connected');

      // Seed categories (safe)
      const defaults = [
        { name: 'Video Templates', icon: '🎬' },
        { name: 'Project Files', icon: '📁' },
        { name: 'Fonts', icon: '🔤' },
        { name: 'Effects', icon: '✨' },
        { name: 'Graphics', icon: '🎨' }
      ];

      for (const c of defaults) {
        await Category.findOneAndUpdate({ name: c.name }, c, { upsert: true });
      }
    } catch (err) {
      console.error('⚠️ MongoDB not connected - app will run with limited functionality');
      console.error(err.message);
    }
  })();
}

startServer();

/* =======================
   SAFETY
======================= */

process.on('unhandledRejection', err => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', err => {
  console.error('Uncaught Exception:', err);
});
