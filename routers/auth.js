const express = require("express");
const { register, login, logout, deleteAllUsers, verifyOtp, forgotPassword, resetPassword, changePassword, refreshAccessToken } = require("../controllers/auth");
const { getAccessToRoute } = require("../middlewares/authorization/auth");
const router = express.Router();
const User = require("../models/user");
const BlacklistToken = require("../models/blackListModel");
// Public routes
router.post("/REGISTER", register);
router.post("/LOGIN", login);
router.post("/LOGOUT", logout);
router.post('/VERIFYOTP', getAccessToRoute, verifyOtp);
router.post('/FORGOTPASSWORD', forgotPassword);
router.post('/RESETPASSWORD', getAccessToRoute, resetPassword);
router.post('/REFRESHTOKEN', getAccessToRoute,refreshAccessToken);
router.post('/CHANGEPASSWORD', getAccessToRoute, changePassword);
router.delete("/DELETEUSERS", deleteAllUsers);

router.get('/PROFILE', getAccessToRoute, (req, res) => {
    res.json({
        message: "Access granted",
        user: req.user,
    });
});
router.get("/GETALLUSERS", async (req, res) => {
    try {
        // Sare users ka data database se nikalte hai
        const users = await User.find();  // Finds all users

        // Response me sare users ka data bhej rahe hai
        res.json({
            success: true,
            message: "All users data fetched successfully",
            data: users  // Sare users ka data
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: "Error fetching users data",
            error: err.message
        });
    }
});
router.get("/GETBLACKLISTEDTOKEN", getAccessToRoute, async (req, res) => {
    try {
        // Sare users ka data database se nikalte hai
        const users = await BlacklistToken.find();  // Finds all users

        // Response me sare users ka data bhej rahe hai
        res.json({
            success: true,
            message: "All users data fetched successfully",
            data: users  // Sare users ka data
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: "Error fetching users data",
            error: err.message
        });
    }
});


module.exports = router;
