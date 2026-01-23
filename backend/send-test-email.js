const path = require('path');
require('dotenv').config({ path: path.join(__dirname, 'env.development') });
const { sendEmail } = require('./utils/email');

(async () => {
  try {
    const to = process.env.EMAIL_USER;
    await sendEmail(to, 'VideoStore Backend Test Email', '<p>This is a test email from VideoStore backend.</p>');
  } catch (err) {
    console.error('Test send error:', err);
  }
})();
