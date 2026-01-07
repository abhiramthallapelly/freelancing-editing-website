#!/usr/bin/env node

/**
 * Build script for Render deployment
 * Installs backend dependencies
 * This is called after npm install (which installs root dependencies)
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

console.log('🔨 Starting build process...');
console.log('📦 Step 1: Root dependencies should already be installed');
console.log('📦 Step 2: Installing backend dependencies...');

const backendPath = path.join(__dirname, 'backend');
const packageJsonPath = path.join(backendPath, 'package.json');

if (!fs.existsSync(backendPath)) {
  console.error('❌ Backend directory not found:', backendPath);
  process.exit(1);
}

if (!fs.existsSync(packageJsonPath)) {
  console.error('❌ Backend package.json not found:', packageJsonPath);
  process.exit(1);
}

try {
  execSync('npm install', {
    stdio: 'inherit',
    cwd: backendPath,
    env: process.env
  });
  console.log('✅ Backend dependencies installed successfully');
} catch (error) {
  console.error('❌ Failed to install backend dependencies');
  console.error(error.message);
  process.exit(1);
}

console.log('✅ Build completed successfully');

