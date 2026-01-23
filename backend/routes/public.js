const express = require('express');
const db = require('../config/db');
const path = require('path');
const fs = require('fs');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const { validateContact, validateReview } = require('../middleware/validator');
const { MongoClient } = require('mongodb'); // Correct MongoDB import
const mongoose = require('mongoose'); // Use mongoose for MongoDB operations

// Define the Review schema (if not already defined elsewhere)
const reviewSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
  rating: Number,
  created_at: { type: Date, default: Date.now },
  timestamp: Date
});

const Review = mongoose.model('Review', reviewSchema); // Create the Review model

const router = express.Router();

// In-memory cart storage (in production, use Redis or database)
const carts = new Map();

// Helper function to get valid origin
const getValidOrigin = (req) => {
  const origin = req.headers.origin || req.headers.host || 'http://localhost:3000';
  // Ensure it's a valid URL
  if (!origin.startsWith('http://') && !origin.startsWith('https://')) {
    return `http://${origin}`;
  }
  return origin;
};

// List all projects/templates (public)
router.get('/projects', (req, res) => {
  db.all('SELECT id, title, description, is_free, price, created_at, file_path, image_path FROM projects ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching projects.' });
    res.json(rows);
  });
});

// List all templates specifically
router.get('/templates', (req, res) => {
  db.all('SELECT id, title, description, is_free, price, created_at, file_path, image_path FROM projects WHERE title LIKE "%template%" OR description LIKE "%template%" ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching templates.' });
    res.json(rows);
  });
});

// Get cart items
router.get('/cart/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const cart = carts.get(sessionId) || [];
  res.json(cart);
});

// Add item to cart
router.post('/cart/:sessionId/add', (req, res) => {
  const { sessionId } = req.params;
  const { projectId } = req.body;
  
  if (!projectId) {
    return res.status(400).json({ message: 'Project ID is required.' });
  }
  
  db.get('SELECT * FROM projects WHERE id = ?', [projectId], (err, project) => {
    if (err) return res.status(500).json({ message: 'Error fetching project.' });
    if (!project) return res.status(404).json({ message: 'Project not found.' });
    
    let cart = carts.get(sessionId) || [];
    
    // Check if item already exists in cart
    const existingItem = cart.find(item => item.id === project.id);
    if (existingItem) {
      return res.status(400).json({ message: 'Item already in cart.' });
    }
    
    // Add item to cart
    cart.push({
      id: project.id,
      title: project.title,
      description: project.description,
      price: project.price,
      is_free: project.is_free,
      file_path: project.file_path
    });
    
    carts.set(sessionId, cart);
    res.json({ message: 'Item added to cart', cart });
  });
});

// Remove item from cart
router.delete('/cart/:sessionId/remove/:projectId', (req, res) => {
  const { sessionId, projectId } = req.params;
  
  let cart = carts.get(sessionId) || [];
  cart = cart.filter(item => item.id !== parseInt(projectId));
  carts.set(sessionId, cart);
  
  res.json({ message: 'Item removed from cart', cart });
});

// Clear cart
router.delete('/cart/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  carts.delete(sessionId);
  res.json({ message: 'Cart cleared' });
});

// Create checkout session for cart
router.post('/cart/:sessionId/checkout', async (req, res) => {
  const { sessionId } = req.params;
  const cart = carts.get(sessionId) || [];
  
  if (cart.length === 0) {
    return res.status(400).json({ message: 'Cart is empty.' });
  }
  
  // Filter out free items (they don't need payment)
  const paidItems = cart.filter(item => item.is_free !== 1);
  
  if (paidItems.length === 0) {
    // All items are free, return success immediately
    return res.json({ 
      success: true, 
      message: 'All items are free!', 
      freeItems: cart,
      sessionId: sessionId 
    });
  }
  
  try {
    const lineItems = paidItems.map(item => ({
      price_data: {
        currency: 'usd',
        product_data: {
          name: item.title,
          description: item.description || 'Professional editing template',
        },
        unit_amount: item.price * 100, // price in cents
      },
      quantity: 1,
    }));
    
    const origin = getValidOrigin(req);
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: lineItems,
      mode: 'payment',
      success_url: `${origin}/download-success?session_id={CHECKOUT_SESSION_ID}&cart_session=${sessionId}`,
      cancel_url: `${origin}/download-cancel`,
      metadata: {
        cart_session: sessionId,
        project_ids: paidItems.map(item => item.id).join(',')
      }
    });
    
    res.json({ url: session.url });
  } catch (error) {
    console.error('Stripe session error:', error);
    res.status(500).json({ message: 'Failed to create checkout session.' });
  }
});

// Download free file with forced download for all file types
router.get('/download/:id', (req, res) => {
  const { id } = req.params;
  db.get('SELECT * FROM projects WHERE id = ?', [id], (err, project) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error.' });
    }
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found.' });
    }
    
    if (project.is_free !== 1) {
      return res.status(403).json({ message: 'This file is not free.' });
    }
    
    // Files are stored in uploads directory, file_path contains just the filename
    const uploadsDir = path.join(__dirname, '../uploads');
    const filePath = path.join(uploadsDir, project.file_path);
    
    if (!fs.existsSync(filePath)) {
      console.error('File not found at path:', filePath);
      console.error('Project file_path from DB:', project.file_path);
      return res.status(404).json({ message: 'File not found. Please contact support.' });
    }
    
    // Force download for all file types
    res.setHeader('Content-Disposition', `attachment; filename="${project.file_path}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.download(filePath, project.file_path, (err) => {
      if (err) {
        console.error('Download error:', err);
        if (!res.headersSent) {
          res.status(500).json({ message: 'Error downloading file' });
        }
      }
    });
  });
});

// Create Stripe Checkout session for paid file
router.post('/create-checkout-session', async (req, res) => {
  const { projectId } = req.body;
  db.get('SELECT * FROM projects WHERE id = ?', [projectId], async (err, project) => {
    if (!project) return res.status(404).json({ message: 'Project not found.' });
    if (project.is_free === 1) return res.status(400).json({ message: 'This file is free.' });
    try {
      const origin = getValidOrigin(req);
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: {
              name: project.title,
              description: project.description,
            },
            unit_amount: project.price * 100, // price in cents
          },
          quantity: 1,
        }],
        mode: 'payment',
        success_url: `${origin}/download-success?session_id={CHECKOUT_SESSION_ID}&project_id=${project.id}`,
        cancel_url: `${origin}/download-cancel`,
        metadata: {
          project_id: project.id
        }
      });
      res.json({ url: session.url });
    } catch (error) {
      res.status(500).json({ message: 'Stripe session error.' });
    }
  });
});

// Stripe webhook endpoint
router.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;
  try {
    if (endpointSecret) {
      const sig = req.headers['stripe-signature'];
      event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } else {
      event = req.body;
    }
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle successful payment
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
  }
  res.json({ received: true });
});

// Download paid file after payment with forced download
router.get('/download-paid/:session_id', async (req, res) => {
  const { session_id } = req.params;
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid') {
      return res.status(403).json({ message: 'Payment not completed.' });
    }
    const projectId = session.metadata.project_id;
    db.get('SELECT * FROM projects WHERE id = ?', [projectId], (err, project) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Database error.' });
      }
      
      if (!project) {
        return res.status(404).json({ message: 'Project not found.' });
      }
      
      // Files are stored in uploads directory, file_path contains just the filename
      const uploadsDir = path.join(__dirname, '../uploads');
      const filePath = path.join(uploadsDir, project.file_path);
      
      if (!fs.existsSync(filePath)) {
        console.error('File not found at path:', filePath);
        console.error('Project file_path from DB:', project.file_path);
        return res.status(404).json({ message: 'File not found. Please contact support.' });
      }
      
      // Force download for all file types
      res.setHeader('Content-Disposition', `attachment; filename="${project.file_path}"`);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.download(filePath, project.file_path, (err) => {
        if (err) {
          console.error('Download error:', err);
          if (!res.headersSent) {
            res.status(500).json({ message: 'Error downloading file' });
          }
        }
      });
    });
  } catch (error) {
    res.status(400).json({ message: 'Invalid session.' });
  }
});

// Contact form submission
router.post('/contact', validateContact, async (req, res) => {
  try {
    const { name, email, message, subject } = req.body;
    
    // Validation
    if (!name || !email || !message) {
      return res.status(400).json({ 
        message: 'Name, email, and message are required.' 
      });
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        message: 'Please enter a valid email address.' 
      });
    }
    
    // Store contact message in database
    db.run(
      'INSERT INTO contacts (name, email, message, subject) VALUES (?, ?, ?, ?)',
      [name.trim(), email.trim(), message.trim(), subject ? subject.trim() : null],
      function(err) {
        if (err) {
          console.error('Database error:', err);
          // Continue even if database fails
        } else {
          console.log('Contact saved to database with ID:', this.lastID);
        }
      }
    );
    
    // Send email notification (if configured)
    const { sendEmail } = require('../utils/email');
    if (process.env.EMAIL_USER) {
      await sendEmail(
        process.env.EMAIL_USER,
        `New Contact Form Submission: ${subject || 'No Subject'}`,
        `
          <h2>New Contact Form Submission</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Subject:</strong> ${subject || 'No Subject'}</p>
          <p><strong>Message:</strong></p>
          <p>${message}</p>
        `
      );
    }
    
    console.log('New Contact Form Submission:', {
      name,
      email,
      message,
      subject,
      timestamp: new Date().toISOString()
    });
    
    res.json({ 
      message: 'Thank you for your message! We\'ll get back to you within 24 hours.',
      success: true
    });
    
  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).json({ 
      message: 'Something went wrong. Please try again later.' 
    });
  }
});

// Review submission with Google Sheets integration
router.post('/review', validateReview, async (req, res) => {
  try {
    const { name, email, message, rating } = req.body;
    
    // Validation
    if (!name || !message || !rating) {
      return res.status(400).json({ 
        message: 'Name, message, and rating are required.' 
      });
    }
    
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ 
        message: 'Rating must be between 1 and 5.' 
      });
    }
    
    // Email validation if provided
    if (email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ 
          message: 'Please enter a valid email address.' 
        });
      }
    }
    
    const reviewData = {
      name: name.trim(),
      email: email ? email.trim() : '',
      message: message.trim(),
      rating: parseInt(rating),
      timestamp: new Date().toISOString()
    };
    
    // Save to database (SQLite)
    db.run(
      'INSERT INTO reviews (name, email, message, rating, created_at) VALUES (?, ?, ?, ?, ?)',
      [reviewData.name, reviewData.email, reviewData.message, reviewData.rating, reviewData.timestamp],
      function(err) {
        if (err) {
          console.error('Database error:', err);
          // Continue even if database fails, try Google Sheets
        } else {
          console.log('Review saved to database with ID:', this.lastID);
        }
      }
    );
    
    // Save to Google Sheets if URL is configured
    const googleSheetsUrl = process.env.GOOGLE_SHEETS_WEB_APP_URL;
    if (googleSheetsUrl) {
      try {
        const sheetsResponse = await fetch(googleSheetsUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            action: 'append',
            data: reviewData
          })
        });
        
        if (sheetsResponse.ok) {
          console.log('Review saved to Google Sheets');
        } else {
          console.log('Google Sheets save failed, but review saved to database');
        }
      } catch (sheetsError) {
        console.error('Google Sheets error:', sheetsError);
        // Continue even if Google Sheets fails
      }
    }
    
    console.log('New Review Submission:', reviewData);
    
    res.json({ 
      message: 'Thank you for your review! We appreciate your feedback.',
      success: true
    });
    
  } catch (error) {
    console.error('Review submission error:', error);
    res.status(500).json({ 
      message: 'Something went wrong. Please try again later.' 
    });
  }
});

// Get reviews from database and Google Sheets
router.get('/reviews', async (req, res) => {
  try {
    // Fetch reviews, ordered by newest first, limit to 200
    const reviews = await Review.find()
      .sort({ created_at: -1 })
      .limit(200);

    // Format reviews
    const formattedReviews = reviews.map(row => ({
      id: row._id,
      name: row.name,
      email: row.email, // Can be filtered out in production if needed
      message: row.message,
      rating: row.rating,
      timestamp: row.created_at || row.timestamp,
      created_at: row.created_at || row.timestamp
    }));

    res.json(formattedReviews);
  } catch (error) {
    console.error('Get reviews error:', error);
    res.status(500).json({ 
      message: 'Failed to fetch reviews.' 
    });
  }
});

module.exports = router;