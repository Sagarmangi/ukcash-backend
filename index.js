require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const authRoutes = require("./Routes/AuthRoutes");
const session = require("express-session");
const multer = require("multer");

const app = express();

app.listen(8080, (err) => {
  if (err) {
    console.log(err);
  } else {
    console.log("Server started on Port 8080");
  }
});

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("DB connected successfully");
  })
  .catch((err) => {
    console.log(err.message);
  });

app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST", "DELETE", "UPDATE", "PUT"],
    credentials: true,
  })
);

app.use(cookieParser());

app.use(express.json());

app.use("/", authRoutes);
