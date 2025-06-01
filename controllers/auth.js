const asyncErrorWrapper = require("express-async-handler");
const User = require("../models/user");
const BlacklistToken = require("../models/blackListModel");
const bcrypt = require('bcryptjs');
const { sendEmail } = require('../services/emailService');  // Your email service to send OTP
const otpTemplate = require('../templates/otpTemplate');
const { sendToken } = require("../helpers/auth/tokenHelpers");
const { validateUserInput, comparePassword } = require("../helpers/input/inputHelpers");
const { isEmail, isStrongPassword } = require("validator");
const createResponse = require("../helpers/responseHelper");
const { generateJwtSecret } = require("../utils/utilfunctions");
const jwt = require("jsonwebtoken");
const { generateUniqueOtp } = require("../helpers/auth/otpHelper");


const register = asyncErrorWrapper(async (req, res, next) => {
    const { username, email, password, mobileNumber } = req.body;

    // Validate input
    const validationErrors = [
        (!username || username.trim().length < 3 || username.trim().length > 50) && "Username must be between 3 and 50 characters long.",
        !isEmail(email) && "Invalid email format. Please provide a valid email.",
        !isStrongPassword(password) && "Password must be at least 8 characters long, include uppercase and lowercase letters, a number, a special character, and must not be easily guessable.",
        (!mobileNumber || !/^\d{10}$/.test(mobileNumber)) && "Mobile number must be a valid 10-digit number."
    ].filter(Boolean);

    if (validationErrors.length) {
        return res.status(400).json(createResponse(400, validationErrors.join(" ")));
    }

    // Check for existing user by email, username, or mobile number
    const existingUser = await User.findOne({ 
        $or: [{ email }, { username }, { mobileNumber }] 
    });

    const errorMessages = [];
    if (existingUser) {
        if (existingUser.email === email) {
            errorMessages.push("Email already registered. Please choose a different one.");
        }
        if (existingUser.username === username) {
            errorMessages.push("Username already registered. Please choose a different one.");
        }
        if (existingUser.mobileNumber === mobileNumber) {
            errorMessages.push("Mobile number already registered. Please choose a different one.");
        }
    }

    if (errorMessages.length) {
        return res.status(400).json(createResponse(400, errorMessages.join(" ")));
    }

    // Create new user and omit sensitive data in response
    const newUser = await User.create({ username, email, password, mobileNumber });
    const { password: _, resetPasswordToken, resetPasswordExpire, failedLoginAttempts, isBlocked, ...userData } = newUser.toObject();

    return res.status(201).json(createResponse(201, "User registered successfully.", [userData]));
});
const login = asyncErrorWrapper(async (req, res, next) => {
  const { email, password } = req.body;

  // Check if the token is blacklisted
  const blacklistedToken = await BlacklistToken.findOne({
    token: req.headers.authorization?.split(" ")[1],
  });

  if (blacklistedToken) {
    return res.status(401).json({
      success: false,
      message: "Token is blacklisted. Please log in again.",
    });
  }

  // Validate input
  if (!email || !password) {
    return res.status(400).json(createResponse(400, "Email and password are required."));
  }

  // Find the user by email
  const user = await User.findOne({ email }).select("+password");
  if (!user) {
    return res.status(404).json(createResponse(404, "Invalid email or password."));
  }

  const now = new Date();

  // Check if the user is blocked
  if (user.isBlocked && user.blockExpires && now <= user.blockExpires) {
    return res
      .status(403)
      .json(createResponse(403, "Account blocked. Try again later."));
  }

  // Check if the password matches
  const isPasswordMatch = await user.comparePassword(password);
  if (!isPasswordMatch) {
    user.failedLoginAttempts += 1;

    if (user.failedLoginAttempts >= 3) {
      user.isBlocked = true;
      user.blockExpires = new Date(now.getTime() + 60 * 60 * 1000); // Block for 1 hour
    }

    await user.save();
    return res.status(user.isBlocked ? 403 : 401).json(
      createResponse(
        user.isBlocked ? 403 : 401,
        user.isBlocked
          ? "Account blocked due to failed attempts."
          : `Invalid password. ${3 - user.failedLoginAttempts} attempts left.`
      )
    );
  }

  // Reset failed login attempts
  user.failedLoginAttempts = 0;
  user.isBlocked = false;
  user.blockExpires = null;

  // Generate and save OTP
  const otp = await generateUniqueOtp(user);
  // const otp = crypto.randomInt(100000, 999999);
  user.otp = otp;
  user.otpExpires = new Date(now.getTime() + 5 * 60 * 1000); // OTP valid for 5 minutes
  await user.save();

  // Send OTP email
  await sendEmail(
    user.email,
    "Your OTP Code for Login",
    otpTemplate(otp, user.username || "User", now.toLocaleDateString())
  );

  // Generate temporary token (prelogin token) with `role: 'temp'`
  const tempTokenPayload = {
    id: user._id,
    email:user.email,
    role: "temp",
  };
  const JWT_SECRET_KEY = generateJwtSecret();

  const preloginToken = jwt.sign(tempTokenPayload,JWT_SECRET_KEY, {
    expiresIn: "5m", // Temporary token valid for 5 minutes
  });

  // Respond with temporary token
  return res.status(200).json(
    createResponse(200, "OTP sent successfully to your email.", {
      otpSent: true,
      preloginToken, 
    })
  );
});
const refreshAccessToken = asyncErrorWrapper(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  const oldAccessToken = req.headers.authorization?.split(" ")[1];

  // Check if the access token is missing
  if (!oldAccessToken) {
    return res.status(400).json({
      status: 400,
      message: "Access token is missing. Please log in again."
    });
  }

  if (!refreshToken) {
    return res.status(401).json({
      status: 401,
      message: "Refresh token is missing. Please log in again.",
    });
  }

  const REFRESH_TOKEN_SECRET = generateJwtSecret();

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    console.log("Decoded refresh token:", decoded);

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({
        status: 404,
        message: "User not found. Please log in again.",
      });
    }

    if (user.refreshToken !== refreshToken) {
      return res.status(403).json({
        status: 403,
        message: "Invalid or revoked refresh token. Please log in again.",
      });
    }

    const newAccessToken = user.getSignedJwtToken();
    const newRefreshToken = user.getSignedRefreshToken();

    await BlacklistToken.create({ token: oldAccessToken });

    user.refreshToken = newRefreshToken;
    await user.save();

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Set cookie only in production environment
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
    });

    return res.status(200).json({
      status: 200,
      message: "Access token refreshed successfully.",
      accessToken: {
        token: newAccessToken,
        type: "Bearer",
        expiresIn: "15m", // Access token expires in 15 minutes
      },
    });
  } catch (error) {
    console.error("Error in verifying refresh token:", error.message);
    console.error("Stack trace:", error.stack);

    // Handle specific error types
    if (error.name === "TokenExpiredError") {
      return res.status(403).json({
        status: 403,
        message: "Refresh token has expired. Please log in again.",
      });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(403).json({
        status: 403,
        message: "Invalid refresh token. Please log in again.",
      });
    }

    // General error handler for unexpected errors
    return res.status(500).json({
      status: 500,
      message: "An error occurred while refreshing the token. Please try again later.",
    });
  }
});


const verifyOtp = asyncErrorWrapper(async (req, res, next) => {
  const { email, otp, tran_type } = req.body;

  if (!email || !otp || !tran_type) {
    return res
      .status(400)
      .json(createResponse(400, "Email, OTP, and tran_type are required."));
  }

  const user = await User.findOne({ email });
  console.log("userdata",user);
  if (!user) {
    return res.status(404).json(createResponse(404, "User not found."));
  }

  if (new Date() > user.otpExpires) {
    return res.status(400).json(createResponse(400, "OTP has expired."));
  }

  if (user.otp !== parseInt(otp, 10)) {
    return res.status(400).json(createResponse(400, "Invalid OTP."));
  }

  // Clear OTP and its expiry
  user.otp = undefined;
  user.otpExpires = undefined;
  await user.save();

  switch (tran_type) {
    case "LOGIN":
      // Generate tokens
      const accessToken = user.getSignedJwtToken();
      const refreshToken = user.getSignedRefreshToken();

      // Save refresh token in the database
      user.refreshToken = refreshToken;
      await user.save();

      // Set refresh token in cookie
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Send access token in response
      return res.status(200).json({
        status: 200,
        message: "Login successful! OTP verified!",
        data: {
           data:user,
          accessToken: {
            token: accessToken,
            type: "Bearer",
            expiresIn: "15m",
          },
        },
      });

    case "RESET_PASSWORD":
      return res
        .status(200)
        .json(createResponse(200, "OTP verified! Proceed to reset password."));

    default:
      return res
        .status(400)
        .json(createResponse(400, "Invalid tran_type provided."));
  }
});
const logout = asyncErrorWrapper(async (req, res, next)=>{
    const accessToken = req.headers.authorization?.split(" ")[1];

    try {
        // Add the token to blacklist
        await BlacklistToken.create({ token: accessToken });

        res.status(200).json({
            success: true,
            message: "Logged out successfully. Token blacklisted.",
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: "Something went wrong during logout.",
            error: err.message,
        });
    }
});
const deleteAllUsers = asyncErrorWrapper(async (req, res, next) => {
  try {
    // Delete all users from the database
    const result = await User.deleteMany();

    return res.status(200).json(
      createResponse(200, "All users have been successfully deleted.", {
        deletedCount: result.deletedCount,
      })
    );
  } catch (error) {
    return res.status(500).json(
      createResponse(500, "An error occurred while deleting users.", {
        error: error.message,
      })
    );
  }
});
const forgotPassword = asyncErrorWrapper(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json(createResponse(400, "Email is required for password reset."));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json(createResponse(404, "User not found."));
  }

  // Generate OTP for the user
  const otp = await generateUniqueOtp(user);
  const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP expiry time (10 minutes)

  user.otp = otp;
  user.otpExpires = otpExpires;
  await user.save();

  // Generate the reset token
  const JWT_SECRET_KEY = generateJwtSecret();
  const resetToken = jwt.sign(
    { id: user._id, role: "reset" },
    JWT_SECRET_KEY,
    { expiresIn: "15m" } // Reset token valid for 15 minutes
  );

  // Prepare email content
  const now = new Date(); // Current date for the template

  try {
    // Use your sendEmail function
    await sendEmail(
      user.email,
      "Your OTP Code for Password Reset",
      otpTemplate(otp, user.username || "User", now.toLocaleDateString())
    );
  } catch (error) {
    console.error("Error sending email:", error);
    return res
      .status(500)
      .json(createResponse(500, "Failed to send OTP email. Please try again."));
  }

  // Respond with success message and reset token
  return res.status(200).json({
    status: 200,
    message: "OTP sent to your email. Please verify the OTP to proceed.",
    resetToken: {
      token: resetToken,
      expiresIn: 900, // Token expiration in seconds
    },
  });
});
const resetPassword = asyncErrorWrapper(async (req, res, next) => {
  const { email, newPassword, confirmPassword } = req.body;

  if (!email || !newPassword || !confirmPassword) {
    return res
      .status(400)
      .json(createResponse(400, "Email, new password, and confirm password are required."));
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json(createResponse(400, "Passwords do not match."));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json(createResponse(404, "User not found."));
  }

  user.password = newPassword; 
  await user.save();

  res
    .status(200)
    .json(createResponse(200, "Password reset successful. You can now log in with your new password."));
});
const changePassword = asyncErrorWrapper(async (req, res, next) => {
  const { oldPassword, newPassword, confirmNewPassword } = req.body;

  // Validate required fields
  if (!oldPassword || !newPassword || !confirmNewPassword) {
    return res
      .status(400)
      .json(createResponse(400, "All fields are required: oldPassword, newPassword, confirmNewPassword."));
  }

  // Check if new passwords match
  if (newPassword !== confirmNewPassword) {
    return res
      .status(400)
      .json(createResponse(400, "New password and confirm password do not match."));
  }

  // Fetch user by ID (using authenticated user ID from the token)
  const user = await User.findById(req.user.id).select("+password");

  if (!user) {
    return res.status(404).json(createResponse(404, "User not found."));
  }

  // Verify the old password
  const isMatch = await user.comparePassword(oldPassword);
  if (!isMatch) {
    return res
      .status(400)
      .json(createResponse(400, "Old password is incorrect."));
  }

  // Update the password (hashing will occur due to UserSchema pre-save middleware)
  user.password = newPassword; 
  await user.save();

  return res.status(200).json(createResponse(200, "Password changed successfully."));
});



module.exports = {
    register,
    login,
    logout,
    verifyOtp,
    deleteAllUsers,
    forgotPassword,
    resetPassword,
    changePassword,
    refreshAccessToken
};

