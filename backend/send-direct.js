const nodemailer = require('nodemailer');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, 'env.development') });

(async () => {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });
    await transporter.sendMail({
      from: `"VideoStore Test" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      subject: 'Direct SMTP test',
      text: 'Direct test',
      html: '<p>Direct test</p>'
    });
  } catch (err) {
    console.error('Send error:', err && (err.message || err));
  }
})();
