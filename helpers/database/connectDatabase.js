const mongoose = require('mongoose');
mongoose.set("strictQuery", true); // Suppress the warning by explicitly setting strictQuery

const connectMongoDB = () => {
  // console.log("MONGO_URL",process.env.MONGO_URl)
  mongoose.connect(process.env.MONGO_URL)
  
    .then(() => {
      console.log("MongoDB connected");
    })
    .catch((err) => {
      console.log("Error connecting MongoDB", err);
    });
};



const connectDatabase = () => {
  connectMongoDB();

};

module.exports = connectDatabase;
