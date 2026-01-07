#!/bin/bash
# Build script for Render deployment
# This ensures backend dependencies are installed

echo "🔨 Starting Render build process..."

# Install root dependencies
echo "📦 Step 1: Installing root dependencies..."
npm install

# Install backend dependencies explicitly
echo "📦 Step 2: Installing backend dependencies..."
cd backend && npm install && cd ..

echo "✅ Build completed successfully"

