// responseHelper.js
const createResponse = (statusCode, message, data = null) => {
    return {
        STATUS: statusCode >= 200 && statusCode < 300 ? "0" : "1", // 0 for success, 1 for error
        MESSAGE: message,
        RESPONSE: data!==null?data:[], // Corrected typo from RESPONE to RESPONSE
    };
};

module.exports = createResponse;
