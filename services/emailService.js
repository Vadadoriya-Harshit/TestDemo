const nodemailer = require('nodemailer');

// SMTP Configurations
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: "587",
  secure: false, // Use TLS
  auth: {
    user: "harshitpatelv9@gmail.com",
    pass: "idnl tbld mbob pinf",
  },
});

/**
 * Send Email with Nodemailer
 * @param {string} to - Recipient's email
 * @param {string} subject - Email subject
 * @param {string} htmlContent - Email HTML content
 * @returns {Promise<boolean>}
 */

const sendEmail = async (to, subject, htmlContent) => {
  try {
    const mailOptions = {
      from: "harshitpatelv9@gmail.com", // Sender address
      to, // Recipient address
      subject, // Subject
      html: htmlContent, // HTML body
    };

    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error(`Failed to send email: ${error.message}`);
    return false;
  }
};

module.exports = { sendEmail };
