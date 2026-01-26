# Video Editing Store - ABHIRAM CREATIONS

## Overview
A video editing services website with a store for templates, project files, fonts, effects, and graphics. Built with Node.js/Express backend serving static HTML frontend.

## Project Structure
```
/
├── backend/           # Express.js server
│   ├── server.js      # Main server entry point
│   ├── routes/        # API routes (admin, auth, store, etc.)
│   ├── models-pg/     # PostgreSQL models
│   ├── config/        # Database configuration (postgres.js)
│   ├── middleware/    # Express middleware
│   └── utils/         # Utility functions
├── index.html         # Main frontend page
├── store.html         # Store page
├── admin-dashboard/   # Admin dashboard (separate React app)
└── package.json       # Root dependencies
```

## Running the Application
- **Workflow**: `Server` - runs `node backend/server.js` on port 5000
- The Express server serves both the API and static frontend files

## Database
- Uses PostgreSQL (Replit's built-in Neon-backed database)
- Connection via `DATABASE_URL` environment variable (auto-configured by Replit)
- Tables: users, projects, categories, reviews, contacts, purchases, wishlists, otps, newsletters

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string (auto-configured by Replit)
- `JWT_SECRET` - Secret for JWT tokens (auto-generated if not set)
- `GOOGLE_CLIENT_ID` - Google OAuth client ID (optional)
- `GOOGLE_CLIENT_SECRET` - Google OAuth secret (optional)
- `EMAIL_USER` - Email for notifications (optional)
- `EMAIL_PASS` - Email password (optional)
- `STRIPE_SECRET_KEY` - Stripe API key for payments (optional)

## API Endpoints
- `/api/health` - Health check (returns DB connection status)
- `/api/auth/*` - Authentication routes (register, login, OTP)
- `/api/store/*` - Store operations (items, categories, purchases)
- `/api/admin/*` - Admin operations
- `/api/public/*` - Public content (reviews, contact form)

## Recent Changes
- 2026-01-26: Migrated from MongoDB to PostgreSQL
  - Created PostgreSQL models in backend/models-pg/
  - Updated all routes to use PostgreSQL
  - Health check now reports PostgreSQL status
  - Authentication (register/login) working with PostgreSQL
- 2026-01-26: Added email OTP verification system
  - OTP codes are 6-digit numbers, valid for 10 minutes
  - Supports signup, login, and password reset flows

## Authentication
- JWT-based authentication
- Password hashing with bcrypt
- Optional Google OAuth support
- OTP verification for email confirmation
