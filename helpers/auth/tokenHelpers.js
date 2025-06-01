const isTokenIncluded =(req) => {
   
    return (
        req.headers.authorization && req.headers.authorization.startsWith("Bearer")
    )

}

const getAccessTokenFromHeader = (req) => {

    const authorization = req.headers.authorization

    const access_token = authorization.split(" ")[1]

    return access_token
}

const sendToken = (user,statusCode ,res,message)=>{

    const TOKEN = user.getSignedJwtToken();  // Assume this function signs the token

    res.status(statusCode).json({
        STATUS: "0",
        TOKEN,
        MESSAGE:message,
        LOGINUSERDETAILS: {
            USERNAME: user.username,
            EMAIL: user.email,
            ROLE: user.role,
            PROFILE_PIC:user.photo,
            WORKING_DATE: user.workindate,
            MACHINE_NM: user.machineName,  // Include machine name
            DISPLAY_LANGUAGE: user.displayLanguage  // Include display language
        }
    });

}

module.exports ={
    sendToken,
    isTokenIncluded,
    getAccessTokenFromHeader
}
