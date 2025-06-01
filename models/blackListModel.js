const mongoose = require('mongoose');

const blacklistTokenSchema = new mongoose.Schema({
    token:{type:String,required:true},
    createdAt:{type:Date,default:Date.now,expires:"1d"},
});
const BlacklistToken = mongoose.model("BlackListToken", blacklistTokenSchema);


module.exports=BlacklistToken;