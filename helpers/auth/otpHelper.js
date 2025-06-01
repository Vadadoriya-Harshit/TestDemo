const crypto = require("crypto");

const generateUniqueOtp = async (user) => {
  let otp;
  const usedOtps = new Set(); // To track previously generated OTPs during this session

  do {
    otp = crypto.randomInt(100000, 999999); // Generate a 6-digit random OTP
  } while (usedOtps.has(otp) || otp === user.otp); // Avoid repetition in this session or the last stored OTP

  usedOtps.add(otp);
  return otp;
};

module.exports = {
  generateUniqueOtp,
};
