
// Load environment variables (Render-safe)
require('dotenv').config();

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

const { initEmailTransporter } = require('./utils/email');
const { connectDB } = require('./config/mongodb');
const Category = require('./models/Category');

console.log(`SERVER_BOOT: loading server with NODE_ENV=${process.env.NODE_ENV || 'development'}`);

const app = express();
const PORT = process.env.PORT || 5050;

// -------------------- SERVER START --------------------
async function startServer() {
  try {
    logger.info('🔄 Connecting to MongoDB...');
    const conn = await connectDB();
    logger.info(`✅ MongoDB connected: ${conn.connection.host}`);

    await seedCategories();
    startHttpServer();
  } catch (err) {
    logger.error('❌ Startup failed:', err.message);
    if (process.env.NODE_ENV === 'production') return;
    startHttpServer(); // allow dev mode without DB
  }
}

// -------------------- HTTP SERVER --------------------
function startHttpServer() {
  const server = app.listen(PORT, () => {
    logger.info(`🚀 Server running on port ${PORT}`);
  });

  server.on('error', (err) => {
    logger.error('❌ Server error:', err.message);
  });
}

// -------------------- SEED DATA --------------------
async function seedCategories() {
  try {
    const categories = [
      { name: 'Video Templates', icon: '🎬' },
      { name: 'Project Files', icon: '📁' },
      { name: 'Fonts', icon: '🔤' },
      { name: 'Effects', icon: '✨' },
      { name: 'Graphics', icon: '🎨' }
    ];

    for (const cat of categories) {
      await Category.findOneAndUpdate({ name: cat.name }, cat, { upsert: true });
    }
    logger.info('✅ Default categories ready');
  } catch (err) {
    logger.warn('⚠️ Category seed skipped:', err.message);
  }
}

// -------------------- MIDDLEWARE --------------------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(timeoutHandler(30000));
app.use(connectionErrorHandler);

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// -------------------- ROUTES --------------------
const authLimiterMiddleware =
  process.env.NODE_ENV === 'production' ? authLimiter : (req, res, next) => next();

app.use('/api/admin', apiLimiter, adminRoutes);
app.use('/api/public', apiLimiter, publicRoutes);
app.use('/api/auth', authLimiterMiddleware, authRoutes);
app.use('/api/auth', authLimiterMiddleware, oauthRoutes);
app.use('/api/store', storeLimiter, storeRoutes);
app.use('/api/analytics', apiLimiter, analyticsRoutes);
app.use('/api/wishlist', apiLimiter, wishlistRoutes);
app.use('/api/newsletter', apiLimiter, newsletterRoutes);
app.use('/api/coupons', apiLimiter, couponsRoutes);
app.use('/api/user', apiLimiter, userRoutes);
app.use('/api/backup', apiLimiter, backupRoutes);
app.use('/api/payments', apiLimiter, paymentsRoutes);

// -------------------- HEALTH --------------------
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    env: process.env.NODE_ENV || 'development',
    uptime: process.uptime()
  });
});

// -------------------- STATIC --------------------
app.use(express.static(path.join(__dirname, '..')));

// -------------------- ERRORS --------------------
app.use('/api/*', (req, res) =>
  res.status(404).json({ success: false, message: 'API route not found' })
);

app.use(notFound);
app.use(errorHandler);

// -------------------- PROCESS SAFETY --------------------
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
});

// -------------------- START APP --------------------
initEmailTransporter();
startServer();
