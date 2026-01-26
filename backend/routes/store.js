const express = require('express');
const path = require('path');
const fs = require('fs');
const Project = require('../models/Project');
const Category = require('../models/Category');
const Purchase = require('../models/Purchase');
const Download = require('../models/Download');
const Coupon = require('../models/Coupon');
const CouponUsage = require('../models/CouponUsage');
const { authenticateToken } = require('../middleware/auth');
const { validateSearch } = require('../middleware/validator');
const router = express.Router();

// Get all store items with categories and search
router.get('/items', validateSearch, async (req, res) => {
  try {
    const { search, category, minPrice, maxPrice, sortBy, isFree } = req.query;
    
    // Build MongoDB query
    const query = {};
    
    // Search filter
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Category filter
    if (category && category !== 'all') {
      query.category = category;
    }
    
    // Price filters
    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = parseInt(minPrice);
      if (maxPrice) query.price.$lte = parseInt(maxPrice);
    }
    
    // Free/Paid filter
    if (isFree === 'true') {
      query.is_free = true;
    } else if (isFree === 'false') {
      query.is_free = false;
    }
    
    // Build sort object
    let sort = { createdAt: -1 }; // Default: newest
    switch (sortBy) {
      case 'price_low':
        sort = { price: 1 };
        break;
      case 'price_high':
        sort = { price: -1 };
        break;
      case 'popular':
        sort = { download_count: -1 };
        break;
      case 'newest':
      default:
        sort = { createdAt: -1 };
        break;
    }

    const items = await Project.find(query).sort(sort).lean();
    
    // Get categories for enrichment
    const categories = await Category.find().lean();
    const categoryMap = {};
    categories.forEach(cat => {
      categoryMap[cat.name] = cat;
    });

    // Transform the data to match expected format
    const transformedItems = items.map(item => ({
      ...item,
      id: item._id.toString(),
      category_name: categoryMap[item.category]?.name || item.category || 'template',
      category_icon: categoryMap[item.category]?.icon || '📁',
      created_at: item.createdAt,
      updated_at: item.updatedAt
    }));
    
    res.json(transformedItems);
  } catch (error) {
    console.error('Store items error:', error);
    // Return empty array instead of error when database is unavailable
    res.json([]);
  }
});

// Get store categories
router.get('/categories', async (req, res) => {
  try {
    const categories = await Category.find().sort({ name: 1 }).lean();
    res.json(categories.map(cat => ({
      ...cat,
      id: cat._id.toString()
    })));
  } catch (error) {
    console.error('Categories error:', error);
    // Return default categories when database is unavailable
    res.json([
      { id: '1', name: 'template', icon: '📁', display_name: 'Templates' },
      { id: '2', name: 'font', icon: '🔤', display_name: 'Fonts' },
      { id: '3', name: 'effect', icon: '✨', display_name: 'Effects' },
      { id: '4', name: 'graphic', icon: '🎨', display_name: 'Graphics' }
    ]);
  }
});

// Get store categories placeholder
router.get('/categories-placeholder', async (req, res) => {
  try {
    const categories = await Category.find().sort({ name: 1 }).lean();
    res.json(categories.map(cat => ({
      ...cat,
      id: cat._id.toString()
    })));
  } catch (error) {
    console.error('Categories error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single store item
router.get('/item/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const item = await Project.findById(id).lean();
    
    if (!item) {
      return res.status(404).json({ message: 'Item not found' });
    }

    // Get category info
    const category = await Category.findOne({ name: item.category }).lean();
    
    const response = {
      ...item,
      id: item._id.toString(),
      category_name: category?.name || item.category || 'template',
      category_icon: category?.icon || '📁',
      created_at: item.createdAt,
      updated_at: item.updatedAt
    };

    res.json(response);
  } catch (error) {
    console.error('Store item error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Download item (free or paid)
router.post('/download/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.ip || req.connection.remoteAddress;

    // Get item details
    const item = await Project.findById(id);
    
    if (!item) {
      return res.status(404).json({ message: 'Item not found' });
    }

    // Check if user has already purchased this item (if it's paid)
    if (!item.is_free) {
      const purchase = await Purchase.findOne({
        user_id: userId,
        project_id: id,
        payment_status: 'completed'
      });

      if (!purchase) {
        return res.status(403).json({ 
          message: 'This item requires purchase before download' 
        });
      }
    }

    // Proceed with download
    await proceedWithDownload(item, id, userId, ipAddress, userAgent, res);

  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Helper function to handle file download
async function proceedWithDownload(item, id, userId, ipAddress, userAgent, res) {
  // Check if file exists
  const uploadsDir = path.join(__dirname, '../uploads');
  const filePath = path.join(uploadsDir, item.file_path);
  
  // Verify uploads directory exists
  if (!fs.existsSync(uploadsDir)) {
    console.error('Uploads directory not found:', uploadsDir);
    return res.status(500).json({ message: 'Server configuration error. Please contact support.' });
  }
  
  // Check if file exists
  if (!fs.existsSync(filePath)) {
    console.error('File not found at path:', filePath);
    console.error('Item file_path from DB:', item.file_path);
    console.error('Full resolved path:', path.resolve(filePath));
    console.error('Uploads directory:', uploadsDir);
    
    // List files in uploads directory for debugging
    try {
      const files = fs.readdirSync(uploadsDir);
      console.error('Files in uploads directory:', files.slice(0, 10)); // Show first 10 files
    } catch (err) {
      console.error('Error reading uploads directory:', err);
    }
    
    return res.status(404).json({ 
      message: 'File not found. The file may have been moved or deleted. Please contact support.',
      debug: process.env.NODE_ENV === 'development' ? {
        expectedPath: filePath,
        filePathFromDB: item.file_path
      } : undefined
    });
  }

  // Record download
  try {
    await Download.create({
      user_id: userId,
      project_id: id,
      download_type: item.is_free ? 'free' : 'paid',
      ip_address: ipAddress,
      user_agent: userAgent
    });
  } catch (err) {
    console.error('Error recording download:', err);
  }

  // Update download count
  try {
    await Project.findByIdAndUpdate(id, { $inc: { download_count: 1 } });
  } catch (err) {
    console.error('Error updating download count:', err);
  }

  // Send file for download
  res.download(filePath, path.basename(item.file_path), (err) => {
    if (err) {
      console.error('Download error:', err);
      if (!res.headersSent) {
        res.status(500).json({ message: 'Error downloading file' });
      }
    }
  });
}

// Purchase item
router.post('/purchase/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const { paymentMethodId, couponCode } = req.body;

    // Get item details
    const item = await Project.findById(id);
    
    if (!item) {
      return res.status(404).json({ message: 'Item not found' });
    }

    if (item.is_free) {
      return res.status(400).json({ message: 'This item is free' });
    }

    // Check if already purchased
    const existingPurchase = await Purchase.findOne({
      user_id: userId,
      project_id: id,
      payment_status: 'completed'
    });

    if (existingPurchase) {
      return res.status(400).json({ message: 'Item already purchased' });
    }

    // Calculate final price (with coupon if provided)
    let finalPrice = item.price;
    let discountAmount = 0;
    let couponId = null;

    // Validate and apply coupon if provided
    if (couponCode) {
      const coupon = await Coupon.findOne({ 
        code: couponCode.toUpperCase(), 
        is_active: true 
      });

      if (coupon) {
        const now = new Date();
        // Check coupon validity
        if ((!coupon.valid_from || new Date(coupon.valid_from) <= now) &&
            (!coupon.valid_until || new Date(coupon.valid_until) >= now) &&
            (!coupon.usage_limit || coupon.used_count < coupon.usage_limit) &&
            item.price >= coupon.min_purchase) {
          
          // Calculate discount
          if (coupon.discount_type === 'percentage') {
            discountAmount = Math.round(item.price * coupon.discount_value / 100);
            if (coupon.max_discount && discountAmount > coupon.max_discount) {
              discountAmount = coupon.max_discount;
            }
          } else {
            discountAmount = coupon.discount_value;
          }
          
          finalPrice = Math.max(0, item.price - discountAmount);
          couponId = coupon._id.toString();
        }
      }
    }

    // Record purchase
    // Here you would integrate with Stripe for payment processing
    // For now, we'll simulate a successful payment
    const purchase = await Purchase.create({
      user_id: userId,
      project_id: id,
      amount: finalPrice,
      payment_status: 'completed',
      stripe_payment_id: 'simulated_payment_' + Date.now()
    });

    // Record coupon usage if coupon was applied
    if (couponId && discountAmount > 0) {
      // Increment used_count in coupons table
      await Coupon.findByIdAndUpdate(couponId, { $inc: { used_count: 1 } });
      
      // Record usage in coupon_usage table
      await CouponUsage.create({
        coupon_id: couponId,
        user_id: userId,
        purchase_id: purchase._id.toString(),
        discount_amount: discountAmount
      });
    }

    res.json({ 
      message: 'Purchase successful! You can now download this item.',
      purchaseId: purchase._id.toString(),
      originalAmount: item.price,
      discountAmount: discountAmount,
      finalAmount: finalPrice,
      couponApplied: !!couponId
    });

  } catch (error) {
    console.error('Purchase error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's purchased items
router.get('/my-purchases', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const purchases = await Purchase.find({
      user_id: userId,
      payment_status: 'completed'
    })
    .populate('project_id')
    .sort({ createdAt: -1 })
    .lean();

    const result = purchases.map(purchase => ({
      ...purchase.project_id,
      id: purchase.project_id._id.toString(),
      amount: purchase.amount,
      payment_status: purchase.payment_status,
      purchase_date: purchase.createdAt,
      created_at: purchase.project_id.createdAt,
      updated_at: purchase.project_id.updatedAt
    }));

    res.json(result);
  } catch (error) {
    console.error('My purchases error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's download history
router.get('/my-downloads', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const downloads = await Download.find({ user_id: userId })
      .populate('project_id')
      .sort({ createdAt: -1 })
      .lean();

    const result = downloads.map(download => ({
      ...download.project_id,
      id: download.project_id._id.toString(),
      download_type: download.download_type,
      download_date: download.createdAt,
      created_at: download.project_id.createdAt,
      updated_at: download.project_id.updatedAt
    }));

    res.json(result);
  } catch (error) {
    console.error('My downloads error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
