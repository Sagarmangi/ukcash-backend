const mongoose = require("mongoose");

const submissionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    type: {
      type: String,
      enum: ["deposit", "withdrawal"],
      required: true,
    },
    amount: {
      type: Number,
      required: true,
    },
    paymentMethod: {
      type: String,
      enum: ["bank-transfer", "easypaisa", "jazzcash"],
    },
    paymentGateway: String,
    bankName: String,
    accountName: String,
    accountNumber: String,
    easypaisaDetails: {
      name: String,
      accountNumber: String,
    },
    jazzcashDetails: {
      name: String,
      accountNumber: String,
    },
    file: {
      type: String, // URL or file path to the stored image
    },
    status: {
      type: String,
      enum: ["pending", "approved", "declined"],
      default: "pending",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Submission", submissionSchema);
