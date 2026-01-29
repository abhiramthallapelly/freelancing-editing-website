const express = require('express');
const path = require('path');
const fs = require('fs');
require('dotenv').config();
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;

const { validateContact, validateReview } = require('../middleware/validator');

const Contact = require('../models-pg/Contact');
const Review = require('../models-pg/Review');
const Project = require('../models-pg/Project');

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
router.get('/projects', async (req, res) => {
  try {
    const projects = await Project.find();
    res.json(projects.map(p => ({
      id: p.id,
      title: p.title,
      description: p.description,
      is_free: p.is_free,
      price: p.price,
      created_at: p.created_at,
      file_path: p.file_path,
      image_path: p.image_path
    })));
  } catch (err) {
    console.error('Projects error:', err);
    // Return empty array when database is unavailable
    res.json([]);
  }
});

// List all templates specifically
router.get('/templates', async (req, res) => {
  try {
    const projects = await Project.find();
    const templates = projects.filter(p => 
      (p.title && p.title.toLowerCase().includes('template')) || 
      (p.description && p.description.toLowerCase().includes('template'))
    );
    res.json(templates.map(p => ({
      id: p.id,
      title: p.title,
      description: p.description,
      is_free: p.is_free,
      price: p.price,
      created_at: p.created_at,
      file_path: p.file_path,
      image_path: p.image_path
    })));
  } catch (err) {
    console.error('Templates error:', err);
    // Return empty array when database is unavailable
    res.json([]);
  }
});

// Get cart items
router.get('/cart/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const cart = carts.get(sessionId) || [];
  res.json(cart);
});

// Add item to cart
router.post('/cart/:sessionId/add', async (req, res) => {
  const { sessionId } = req.params;
  const { projectId } = req.body;
  
  if (!projectId) {
    return res.status(400).json({ message: 'Project ID is required.' });
  }
  
  try {
    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ message: 'Project not found.' });
    
    let cart = carts.get(sessionId) || [];
    
    // Check if item already exists in cart
    const existingItem = cart.find(item => item.id === project._id.toString());
    if (existingItem) {
      return res.status(400).json({ message: 'Item already in cart.' });
    }
    
    // Add item to cart
    cart.push({
      id: project._id.toString(),
      title: project.title,
      description: project.description,
      price: project.price,
      is_free: project.is_free,
      file_path: project.file_path
    });
    
    carts.set(sessionId, cart);
    res.json({ message: 'Item added to cart', cart });
  } catch (err) {
    console.error('Cart add error:', err);
    res.status(500).json({ message: 'Error fetching project.' });
  }
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
  
  if (!stripe) {
    return res.status(503).json({ message: 'Payment system not configured. Please contact support.' });
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
router.get('/download/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const project = await Project.findById(id);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found.' });
    }
    
    if (!project.is_free) {
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
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ message: 'Database error.' });
  }
});

// Create Stripe Checkout session for paid file
router.post('/create-checkout-session', async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ message: 'Payment system not configured. Please contact support.' });
  }
  
  const { projectId } = req.body;
  try {
    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ message: 'Project not found.' });
    if (project.is_free) return res.status(400).json({ message: 'This file is free.' });
    
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
      success_url: `${origin}/download-success?session_id={CHECKOUT_SESSION_ID}&project_id=${project._id}`,
      cancel_url: `${origin}/download-cancel`,
      metadata: {
        project_id: project._id.toString()
      }
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error('Stripe session error:', error);
    res.status(500).json({ message: 'Stripe session error.' });
  }
});

// Stripe webhook endpoint
router.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe) {
    return res.status(503).json({ message: 'Payment system not configured.' });
  }
  
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
  if (!stripe) {
    return res.status(503).json({ message: 'Payment system not configured. Please contact support.' });
  }
  
  const { session_id } = req.params;
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== 'paid') {
      return res.status(403).json({ message: 'Payment not completed.' });
    }
    const projectId = session.metadata.project_id;
    const project = await Project.findById(projectId);
    
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
  } catch (error) {
    console.error('Download paid error:', error);
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
    
    try {
      const contact = await Contact.create({
        name: name.trim(),
        email: email.trim(),
        message: message.trim(),
        subject: subject ? subject.trim() : null
      });
      console.log('Contact saved to database with ID:', contact.id);
    } catch (dbErr) {
      console.error('❌ Database error during contact save:', dbErr.message);
      // We continue to send the email even if DB fails
    }
    
    // Send email notification (if configured)
    const { sendEmail } = require('../utils/email');
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      try {
        // Escape HTML in user input and convert newlines to <br>
        const escapeHtml = (text) => {
          if (!text) return '';
          return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;')
            .replace(/\n/g, '<br>');
        };
        
        const htmlMessage = `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { background: #00bfa6; color: white; padding: 20px; text-align: center; }
              .content { padding: 20px; background: #f9f9f9; }
              .field { margin-bottom: 15px; }
              .label { font-weight: bold; color: #555; }
              .message-box { background: white; padding: 15px; border-radius: 5px; margin-top: 10px; border-left: 4px solid #00bfa6; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>New Contact Form Submission</h1>
              </div>
              <div class="content">
                <div class="field">
                  <span class="label">Name:</span> ${escapeHtml(name)}
                </div>
                <div class="field">
                  <span class="label">Email:</span> <a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a>
                </div>
                <div class="field">
                  <span class="label">Subject:</span> ${escapeHtml(subject) || 'No Subject'}
                </div>
                <div class="field">
                  <span class="label">Message:</span>
                  <div class="message-box">
                    ${escapeHtml(message)}
                  </div>
                </div>
              </div>
            </div>
          </body>
          </html>
        `;
        
        const emailSent = await sendEmail(
          process.env.EMAIL_USER,
          `New Contact Form Submission: ${subject || 'No Subject'}`,
          htmlMessage
        );
        
        if (emailSent) {
          console.log('✅ Contact email sent successfully');
        } else {
          console.error('❌ Failed to send contact email notification');
        }
      } catch (emailErr) {
        console.error('❌ Email notification block error:', emailErr.message);
      }
    } else {
      console.warn('⚠️ Email credentials missing, skipping notification');
    }
    
    console.log('New Contact Form Submission:', {
      name,
      email,
      message,
      subject,
      timestamp: new Date().toISOString()
    });
    
    res.status(200).json({ 
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
      rating: parseInt(rating)
    };
    
    // Save to MongoDB
    try {
      const review = await Review.create(reviewData);
      console.log('Review saved to database with ID:', review.id);
    } catch (dbErr) {
      console.error('Database error:', dbErr);
      // Continue even if database fails, try Google Sheets
    }
    
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
    const reviews = await Review.find({
      order: [['created_at', 'DESC']],
      limit: 200
    });

    // Format reviews
    const formattedReviews = reviews.map(row => ({
      id: row.id,
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
    // Return empty array when database is unavailable
    res.json([]);
  }
});

module.exports = router;