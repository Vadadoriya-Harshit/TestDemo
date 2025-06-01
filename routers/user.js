const express = require("express")

const {profile} = require("../Controllers/user");
const { getAccessToRoute } = require("../middlewares/authorization/auth");


const router = express.Router() ;

router.get("/profile",getAccessToRoute ,profile)







module.exports = router