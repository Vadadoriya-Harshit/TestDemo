const crypto = require("crypto");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { isEmail } = require("validator");
const { format } = require("date-fns");
const { generateJwtSecret } = require("../utils/utilfunctions");

const formatWorkingDate = (date) => {
  return format(date, "dd/MMM/yyyy").toUpperCase(); // Example: 22/JUL/2024
};

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Please provide a username"],
      trim: true,
      minlength: [3, "Username must be at least 3 characters long"],
      maxlength: [50, "Username cannot exceed 50 characters"],
    },
    photo: {
      type: String,
      default: "user.png",
    },
    email: {
      type: String,
      required: [true, "Please provide an email"],
      unique: true,
      lowercase: true,
      validate: [isEmail, "Please provide a valid email address"],
    },
    mobileNumber: {
      type: String,
      required: [true, "Please provide a mobile number"],
      unique: true,
      match: [/^\d{10}$/, "Please enter a valid mobile number"], // Ensures 10-digit format
    },
    password: {
      type: String,
      minlength: [6, "Password must be at least 6 characters long"],
      required: [true, "Please provide a password"],
      select: false,
    },
    role: {
      type: String,
      enum: ["user", "admin", "editor"],
      default: "user",
    },
    displayLanguage: {
      type: String,
      default: "en",
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    isBlocked: {
      type: Boolean,
      default: false,
    },
    blockExpires: {
      type: Date,
      default: null,
    },
    otp: {
      type: Number,
    },
    otpExpires: {
      type: Date,
    },
    refreshToken: {
      type: String, // Ensure the type is correct (String in this case)
      default: null, // Default value can be null initially
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
    workindate: {
      type: String,
      default: () => formatWorkingDate(new Date()), // Automatically set to formatted current date
    },
    rawWorkingDate: {
      type: Date,
      default: Date.now, // Raw date for future use in sorting/filtering
    },
    lastLogin: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

UserSchema.pre("save", async function (next) {
  if (!this.workindate) {
    this.workindate = formatWorkingDate(new Date());
  }

  if (this.isModified("email")) {
    this.email = this.email.toLowerCase().trim();
  }

  if (this.isModified("username")) {
    this.username = this.username.trim();
  }

  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }

  next();
});

// Method to compare user password
UserSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

UserSchema.methods.getSignedJwtToken = function () {
  const JWT_SECRET_KEY = generateJwtSecret();
  const JWT_EXPIRE = process.env.JWT_EXPIRE;
  console.log("JWT_SECRET_KEY",JWT_SECRET_KEY);
  console.log("JWT_EXPIRE",process.env.JWT_EXPIRE);
  

  const payload = {
    id: this._id,
    username: this.username,
    email: this.email,
    role: this.role,
  };

  return jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: JWT_EXPIRE });
};
UserSchema.methods.getSignedRefreshToken = function () {
  const payload = { id: this._id };
  const REFRESH_TOKEN_SECRET = generateJwtSecret();
  const expiresIn = process.env.REFRESH_TOKEN_EXPIRATION || "7d";

  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn });
};

UserSchema.methods.getResetPasswordTokenFromUser = function () {
  const RESET_PASSWORD_EXPIRE = 3600000; // Hardcoded expiration: 1 hour in milliseconds
 
  const randomHexString = crypto.randomBytes(20).toString("hex");

  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(randomHexString)
    .digest("hex");

  this.resetPasswordExpire = Date.now() + RESET_PASSWORD_EXPIRE;

  return randomHexString;
};

// Remove sensitive data (like password and reset token) from responses
UserSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.resetPasswordToken;
  delete obj.resetPasswordExpire;
  return obj;
};

const User = mongoose.model("User", UserSchema);

module.exports = User;
