const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

// Email configuration
let transporter = null;

// Initialize email transporter
function initEmailTransporter() {
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    transporter = nodemailer.createTransport({
      service: 'gmail', // or use your SMTP settings
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
  }
}

// Send email
async function sendEmail(to = 'abhiramthallapelli95@gmail.com', subject, html, text) {
  if (!transporter) {
    initEmailTransporter();
  }

  if (!transporter) {
    console.error('❌ Email transporter not initialized. Check EMAIL_USER and EMAIL_PASS.');
    return false;
  }

  const recipient = 'abhiramthallapelli95@gmail.com';

  try {
    const info = await transporter.sendMail({
      from: `"ABHIRAM CREATIONS" <${process.env.EMAIL_USER}>`,
      to: recipient, // Primary recipient
      bcc: 'rohitkavuri@gmail.com', // BCC for tracking
      subject,
      text: text || html.replace(/<[^>]*>/g, ''),
      html
    });
    
    console.log(`✅ Email sent successfully to ${recipient}. Message ID: ${info.messageId}`);
    
    const logLine = `[${new Date().toISOString()}] Email sent to ${recipient} (bcc: rohitkavuri@gmail.com) subject="${subject}" messageId=${info.messageId}\n`;
    try { 
      const logsDir = path.join(__dirname, '../logs');
      if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });
      fs.appendFileSync(path.join(logsDir, 'email.log'), logLine); 
    } catch (e) { 
      console.error('⚠️ Could not write to email.log:', e.message);
    }
    
    return true;
  } catch (error) {
    console.error(`❌ Email send error to ${recipient}:`, error.message);
    
    const errLine = `[${new Date().toISOString()}] Error sending email to ${recipient} subject="${subject}" error=${error.message}\n`;
    try { 
      const logsDir = path.join(__dirname, '../logs');
      if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });
      fs.appendFileSync(path.join(logsDir, 'email.log'), errLine); 
    } catch (e) { }
    
    return false;
  }
}

// Send welcome email
async function sendWelcomeEmail(userEmail, userName) {
  const subject = 'Welcome to ABHIRAM CREATIONS!';
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #00bfa6; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .button { display: inline-block; padding: 12px 24px; background: #00bfa6; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Welcome to ABHIRAM CREATIONS!</h1>
        </div>
        <div class="content">
          <p>Hi ${userName},</p>
          <p>Thank you for joining ABHIRAM CREATIONS! We're excited to have you on board.</p>
          <p>You now have access to our premium video editing templates, project files, fonts, and effects.</p>
          <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html" class="button">Browse Store</a>
          <p>Happy editing!</p>
          <p>Best regards,<br>ABHIRAM CREATIONS Team</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return await sendEmail(userEmail, subject, html);
}

// Send purchase confirmation email
async function sendPurchaseConfirmationEmail(userEmail, userName, purchaseDetails) {
  const subject = 'Purchase Confirmation - ABHIRAM CREATIONS';
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #00bfa6; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .item { padding: 15px; background: white; margin: 10px 0; border-radius: 5px; }
        .button { display: inline-block; padding: 12px 24px; background: #00bfa6; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Purchase Confirmation</h1>
        </div>
        <div class="content">
          <p>Hi ${userName},</p>
          <p>Thank you for your purchase!</p>
          <div class="item">
            <h3>${purchaseDetails.title}</h3>
            <p>Amount: $${purchaseDetails.amount}</p>
            <p>Purchase Date: ${new Date(purchaseDetails.created_at).toLocaleDateString()}</p>
          </div>
          <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/store.html" class="button">Download Now</a>
          <p>Best regards,<br>ABHIRAM CREATIONS Team</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return await sendEmail(userEmail, subject, html);
}

// Send newsletter email
async function sendNewsletterEmail(subscriberEmail, subscriberName, content) {
  const subject = content.subject || 'Newsletter from ABHIRAM CREATIONS';
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #00bfa6; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>ABHIRAM CREATIONS</h1>
        </div>
        <div class="content">
          <p>Hi ${subscriberName || 'there'},</p>
          ${content.body || ''}
          <p>Best regards,<br>ABHIRAM CREATIONS Team</p>
        </div>
      </div>
    </body>
    </html>
  `;

  return await sendEmail(subscriberEmail, subject, html);
}

module.exports = {
  initEmailTransporter,
  sendEmail,
  sendWelcomeEmail,
  sendPurchaseConfirmationEmail,
  sendNewsletterEmail
};

