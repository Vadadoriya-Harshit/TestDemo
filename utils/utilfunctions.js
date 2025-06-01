const crypto = require('crypto');

const generateJwtSecret = () => {
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex'); 
  }
  return process.env.JWT_SECRET;
};

module.exports = {
  generateJwtSecret,
};
