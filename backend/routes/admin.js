const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const multer = require('multer');
const path = require('path');
const verifyAdmin = require('../middleware/auth');
const { uploadLimiter } = require('../middleware/rateLimiter');
const { validateProjectUpload } = require('../middleware/validator');
const Admin = require('../models/Admin');

const router = express.Router();

// Register admin (one-time setup, can be disabled after first use)
router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required.' });
  }
  db.get('SELECT * FROM admin WHERE username = ?', [username], async (err, user) => {
    if (user) {
      return res.status(400).json({ message: 'Admin already exists.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO admin (username, password) VALUES (?, ?)', [username, hashed], function(err) {
      if (err) return res.status(500).json({ message: 'Error creating admin.' });
      res.json({ message: 'Admin registered successfully.' });
    });
  });
});

// Login admin
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required.' });
  }
  try {
    const user = await Admin.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'secret', { expiresIn: '2h' });
    res.json({ token });
  } catch (error) {
    console.error('Error during admin login:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Multer setup for file uploads with multiple files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Check if it's an image file
    if (file.fieldname === 'image') {
      cb(null, path.join(__dirname, '../uploads/images'));
    } else {
      cb(null, path.join(__dirname, '../uploads'));
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// Upload a new project/preset
router.post('/projects', verifyAdmin, uploadLimiter, validateProjectUpload, upload.fields([
  { name: 'file', maxCount: 1 },
  { name: 'image', maxCount: 1 }
]), (req, res) => {
  const { title, description, is_free, price } = req.body;
  if (!title || !req.files.file) {
    return res.status(400).json({ message: 'Title and file are required.' });
  }
  
  const filePath = req.files.file[0].filename;
  const imagePath = req.files.image ? req.files.image[0].filename : null;
  
  db.run(
    'INSERT INTO projects (title, description, file_path, image_path, is_free, price) VALUES (?, ?, ?, ?, ?, ?)',
    [title, description || '', filePath, imagePath, is_free === '0' ? 0 : 1, price || 0],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Error saving project.', error: err.message });
      }
      res.json({ id: this.lastID, message: 'Project uploaded successfully.' });
    }
  );
});



// List all projects (admin view)
router.get('/projects', verifyAdmin, (req, res) => {
  db.all('SELECT * FROM projects ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching projects.' });
    res.json(rows);
  });
});

// Edit a project
router.put('/projects/:id', verifyAdmin, (req, res) => {
  const { title, description, is_free, price } = req.body;
  const { id } = req.params;
  db.run(
    'UPDATE projects SET title = ?, description = ?, is_free = ?, price = ? WHERE id = ?',
    [title, description, is_free === '0' ? 0 : 1, price, id],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error updating project.' });
      res.json({ message: 'Project updated successfully.' });
    }
  );
});

// Delete a project
router.delete('/projects/:id', verifyAdmin, (req, res) => {
  const { id } = req.params;
  db.get('SELECT file_path FROM projects WHERE id = ?', [id], (err, row) => {
    if (row && row.file_path) {
      const fs = require('fs');
      const filePath = path.join(__dirname, '../uploads', row.file_path);
      fs.unlink(filePath, () => {}); // Delete file, ignore errors
    }
    db.run('DELETE FROM projects WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ message: 'Error deleting project.' });
      res.json({ message: 'Project deleted successfully.' });
    });
  });
});

module.exports = router;