const asyncErrorWrapper = require("express-async-handler");
const User = require("../models/userOtpModel");
const OTP = require("../models/otpModell");
const BlacklistToken = require("../models/blackListModel");
const { sendToken } = require("../helpers/auth/tokenHelpers");
const { validateUserInput, comparePassword } = require("../helpers/input/inputHelpers");
const { isEmail, isStrongPassword } = require("validator");
const createResponse = require("../helpers/responseHelper");
const axios = require("axios");

const MSG91_API_KEY = "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";  

const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const register = asyncErrorWrapper(async (req, res, next) => {
    const { username, email, password, mobileNumber } = req.body;

    if (!username || username.length < 3 || username.length > 50) {
        return res.status(400).json(createResponse(400, "Username must be between 3 and 50 characters long."));
    }
    if (!isEmail(email)) {
        return res.status(400).json(createResponse(400, "Invalid email format."));
    }
    if (!isStrongPassword(password)) {
        return res.status(400).json(createResponse(400, "Password must be strong."));
    }
    if (!mobileNumber || !/^\d{10}$/.test(mobileNumber)) {
        return res.status(400).json(createResponse(400, "Invalid mobile number."));
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }, { mobileNumber }] });
    if (existingUser) {
        return res.status(400).json(createResponse(400, "User already exists."));
    }

    const newUser = await User.create({ username, email, password, mobileNumber });
    const { password: _, ...userData } = newUser.toObject();

    return res.status(201).json(createResponse(201, "User registered successfully.", [userData]));
});

const login = asyncErrorWrapper(async (req, res, next) => {
    const { usernameOrMobile, password } = req.body;

    if (!validateUserInput(usernameOrMobile, password)) {
        return res.status(400).json(createResponse(400, "Please check your inputs."));
    }

    const user = await User.findOne({
        $or: [{ username: usernameOrMobile }, { mobileNumber: usernameOrMobile }]
    }).select("+password");

    if (!user) {
        return res.status(404).json(createResponse(404, "Invalid Username or Mobile Number."));
    }

    if (!(await user.comparePassword(password))) {
        return res.status(404).json(createResponse(404, "Invalid password."));
    }

    // Generate OTP and set expiry time
    const otp = generateOTP();
    const expiry = new Date();
    expiry.setMinutes(expiry.getMinutes() + 5);  

    // Save OTP in the database
    await OTP.create({ phoneNumber: user.mobileNumber, otp, expiry });

    // Prepare OTP message
    const message = `Your OTP is ${otp}. It is valid for 5 minutes.`;

    // Log the request before calling MSG91 API
    console.log("Sending OTP request to MSG91 API:");
    console.log({
        authkey: MSG91_API_KEY,
        mobile: `+91${user.mobileNumber}`,
        otp: otp,
        message: message
    });

    try {
        // Call MSG91 API to send OTP
        const response = await axios.post("https://api.msg91.com/api/v5/otp", null, {
            params: {
                authkey: MSG91_API_KEY,
                mobile: `+91${user.mobileNumber}`, // Include country code (+91 for India)
                otp: otp,
                message: message,
            },
        });

        // Log the response from MSG91 API
        console.log("MSG91 API Response:", response.data);

        // Send success response to the user
        return res.status(200).json(createResponse(200, "Login successful. OTP sent to your mobile number.", { mobileNumber: user.mobileNumber }));
    } catch (error) {
        console.error("Error sending OTP:", error);
        return res.status(500).json(createResponse(500, "Failed to send OTP."));
    }
});


const verifyOTP = asyncErrorWrapper(async (req, res, next) => {
    const { phoneNumber, otp } = req.body;

    if (!phoneNumber || !otp) {
        return res.status(400).json(createResponse(400, "Phone number and OTP are required."));
    }

    const otpRecord = await OTP.findOne({ phoneNumber });

    if (!otpRecord) {
        return res.status(404).json(createResponse(404, "OTP not found."));
    }

    if (new Date() > otpRecord.expiry) {
        return res.status(400).json(createResponse(400, "OTP has expired."));
    }

    if (otp !== otpRecord.otp) {
        return res.status(400).json(createResponse(400, "Invalid OTP."));
    }

    const user = await User.findOne({ mobileNumber: phoneNumber });

    if (!user) {
        return res.status(404).json(createResponse(404, "User not found."));
    }

   
    sendToken(user, 200, res);
});

const logout = asyncErrorWrapper(async (req, res, next) => {
    const accessToken = req.headers.authorization?.split(" ")[1];

    try {
       
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
        const result = await User.deleteMany({});

        // Check if there were any users to delete
        if (result.deletedCount === 0) {
            return res.status(404).json(createResponse(404, "No users found to delete."));
        }

        // Return success response
        return res.status(200).json(createResponse(200, `${result.deletedCount} user(s) deleted successfully.`));
    } catch (error) {
        console.error("Error deleting users:", error);
        return res.status(500).json(createResponse(500, "Failed to delete users."));
    }
});

module.exports = { register, login, verifyOTP, logout,deleteAllUsers };


