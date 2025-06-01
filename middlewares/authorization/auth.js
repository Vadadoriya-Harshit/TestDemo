const jwt = require("jsonwebtoken");
const User = require("../../models/user");
const CustomError = require("../errors/customErrorHandler");
const asyncErrorWrapper = require("express-async-handler");
const BlacklistToken = require("../../models/blackListModel"); // Import blacklist model
const { isTokenIncluded, getAccessTokenFromHeader } = require("../../helpers/auth/tokenHelpers");
const { generateJwtSecret } = require("../../utils/utilfunctions");

const getAccessToRoute = asyncErrorWrapper(async (req, res, next) => {
    console.log("Headers received:", req.headers); // Debugging logs

    if (!isTokenIncluded(req)) {
        console.log("Token not found in headers.");
        return next(new CustomError("You are not authorized to access this route", 401));
    }

    const accessToken = getAccessTokenFromHeader(req);
    console.log("Access Token:", accessToken);

    try {
        // Check if token is blacklisted
        const blacklisted = await BlacklistToken.findOne({ token: accessToken });
        if (blacklisted) {
            console.log("Token is blacklisted:", accessToken);
            return next(new CustomError("Token is invalid. Please log in again.", 401));
        }

        const JWT_SECRET_KEY = generateJwtSecret();

        // Verify the token
        const decoded = jwt.verify(accessToken, JWT_SECRET_KEY);
        console.log("Decoded Token:", decoded);

        const user = await User.findById(decoded.id);
        if (!user) {
            console.log("User not found for token ID:", decoded.id);
            return next(new CustomError("User not found", 404));
        }

        // Role-based access logic
        const endpoint = req.originalUrl;

        if (decoded.role === "temp") {
            console.log("Temporary token detected for endpoint:", endpoint);
            if (!endpoint.includes("/VERIFYOTP")) {
                return next(new CustomError("Access denied: OTP verification required.", 403));
            }
        } else if (decoded.role === "reset") {
            console.log("Reset token detected for endpoint:", endpoint);
            if (!(endpoint.includes("/RESETPASSWORD") || endpoint.includes("/VERIFYOTP"))) {
                return next(new CustomError("Access denied: Reset token required for this route.", 403));
            }
        } else if (decoded.role !== "user") {
            return next(new CustomError("Unauthorized: Invalid token role.", 401));
        }

        req.user = user;
        console.log("User attached to req:", req.user);

        next();
    } catch (err) {
        console.log("Token verification error:", err.message);
        return next(new CustomError("Unauthorized: Invalid token", 401));
    }
});



module.exports = { getAccessToRoute };
