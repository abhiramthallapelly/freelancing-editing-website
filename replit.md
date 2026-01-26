# Video Editing Store - ABHIRAM CREATIONS

## Overview
A video editing services website with a store for templates, project files, fonts, effects, and graphics. Built with Node.js/Express backend serving static HTML frontend.

## Project Structure
```
/
├── backend/           # Express.js server
│   ├── server.js      # Main server entry point
│   ├── routes/        # API routes (admin, auth, store, etc.)
│   ├── models/        # Mongoose models
│   ├── middleware/    # Express middleware
│   ├── config/        # Database configuration
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
- Uses MongoDB (mongoose) for data persistence
- Requires `MONGODB_URI` environment variable for connection
- Server runs with limited functionality if MongoDB unavailable

## Environment Variables Needed
- `MONGODB_URI` - MongoDB connection string (required for full functionality)
- `GOOGLE_CLIENT_ID` - Google OAuth client ID (optional)
- `GOOGLE_CLIENT_SECRET` - Google OAuth secret (optional)
- `JWT_SECRET` - Secret for JWT tokens
- `EMAIL_USER` - Email for notifications
- `EMAIL_PASS` - Email password

## API Endpoints
- `/api/health` - Health check
- `/api/auth/*` - Authentication routes
- `/api/store/*` - Store operations
- `/api/admin/*` - Admin operations
- `/api/public/*` - Public content

### OTP Verification Endpoints
- `POST /api/auth/send-otp` - Send 6-digit OTP code to email (types: signup, login, password_reset)
- `POST /api/auth/verify-otp` - Verify OTP code
- `POST /api/auth/register-with-otp` - Register with email verification
- `POST /api/auth/login-with-otp` - Login using OTP instead of password

## Recent Changes
- 2026-01-26: Added email OTP verification system
  - New OTP model for storing verification codes
  - OTP codes are 6-digit numbers, valid for 10 minutes
  - Rate limiting: max 3 OTP requests per email per 10 minutes
  - Max 5 verification attempts per OTP code
  - Supports signup, login, and password reset flows
  - Store/reviews endpoints return empty arrays when MongoDB unavailable
- 2026-01-24: Converted all routes to use MongoDB
  - Fixed download routes (free and paid) to use Project model
  - Fixed contact form to use Contact model + sends email notifications
  - Fixed review submission to use Review model
  - Contact form and email notifications working correctly
- 2026-01-23: Configured for Replit environment
  - Updated server to run on port 5000 (0.0.0.0)
  - Made MongoDB connection non-blocking
  - Added cache control headers for development

## Known Issues
- MongoDB connection string needs to be corrected (current URI contains "200525>" corruption)
- Correct format: `mongodb+srv://username:password@cluster17.jbpc0qx.mongodb.net/database-name`
- OTP verification requires working MongoDB connection to function
