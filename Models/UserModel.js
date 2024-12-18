const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  phoneNumber: {
    type: String,
    required: [true, "Phone number is required"],
    unique: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: [true, "Password is required"],
  },
  paymentMethods: {
    easypaisa: {
      name: String,
      accountNumber: String,
    },
    jazzcash: {
      name: String,
      accountNumber: String,
    },
    bank: {
      bankName: String,
      accountName: String,
      accountNumber: String,
    },
  },
  submissions: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Submission",
    },
  ],
  notifications: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Notification", // Reference to the Notification model
    },
  ],
  accountStatus: {
    type: String,
    enum: ["approved", "unapproved"],
    default: "unapproved",
  },
  role: {
    type: String,
    enum: ["user", "agent", "admin", "super admin"],
    default: "user",
  },
  assignedAgent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
});

// Password hashing middleware
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt();
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    return next(err);
  }
});

// Login method
userSchema.statics.login = async function (phoneNumber, password) {
  const user = await this.findOne({ phoneNumber });
  if (user) {
    const auth = await bcrypt.compare(password, user.password);
    if (auth) {
      return user;
    }
    throw Error("Incorrect password");
  }
  throw Error("Incorrect phone number");
};

module.exports = mongoose.model("User", userSchema);
