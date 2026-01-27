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

const { pool } = require('./config/postgres');
const { initEmailTransporter } = require('./utils/email');

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

app.set('trust proxy', 1);

const PORT = parseInt(process.env.PORT, 10) || 5000;
const HOST = process.env.NODE_ENV === 'production' ? '0.0.0.0' : '0.0.0.0';

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

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '..')));

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

app.get('/api/health', async (req, res) => {
  let dbStatus = 'disconnected';
  try {
    await pool.query('SELECT 1');
    dbStatus = 'connected';
  } catch (err) {
    dbStatus = 'disconnected';
  }
  
  res.json({
    status: 'ok',
    env: process.env.NODE_ENV || 'development',
    db: dbStatus,
    uptime: process.uptime()
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.use(notFound);
app.use(errorHandler);

async function startServer() {
  try {
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server LIVE on 0.0.0.0:${PORT}`);
      initEmailTransporter();
    });

    server.on('error', err => {
      console.error('SERVER ERROR:', err.message);
      if (err.code === 'EADDRINUSE') {
        console.log(`Port ${PORT} is already in use. Retrying on another port...`);
        setTimeout(() => {
          server.close();
          app.listen(0, '0.0.0.0');
        }, 1000);
      }
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }

  try {
    await pool.query('SELECT 1');
    console.log('✅ PostgreSQL connected');
  } catch (err) {
    console.error('⚠️ PostgreSQL connection issue:', err.message);
  }
}

startServer();

process.on('unhandledRejection', err => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', err => {
  console.error('Uncaught Exception:', err);
});
