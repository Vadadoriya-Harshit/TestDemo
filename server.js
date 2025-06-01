const express = require("express")
const dotenv = require("dotenv")
const cors = require("cors")
const path = require("path")
const cookieParser = require("cookie-parser");

const IndexRoute = require("./routers/index");
const connectDatabase = require("./helpers/database/connectDatabase")
const customErrorHandler = require("./middlewares/errors/customErrorHandler")

dotenv.config({
    path:  '.env'
})

connectDatabase()

const app = express() ;

app.use(express.json());
app.use(cors())
app.use(cookieParser());
app.use("/",IndexRoute);

app.use(customErrorHandler)

const PORT = process.env.PORT || 9000;


app.use(express.static(path.join(__dirname , "public") ))

const server = app.listen(PORT,()=>{

    console.log(`Server running on port  ${PORT} : ${process.env.NODE_ENV}`)

})

process.on("unhandledRejection",(err , promise) =>{
    console.log(`Logged Error : ${err}`)

    server.close(()=>process.exit(1))
})