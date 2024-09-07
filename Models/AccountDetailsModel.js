const mongoose = require("mongoose");

const accountDetailsSchema = new mongoose.Schema(
  {
    bankName: { type: String, default: "" },
    bankAccountName: { type: String, default: "" },
    bankAccountNumber: { type: String, default: "" },
    easypaisaAccountName: { type: String, default: "" },
    easypaisaAccountNumber: { type: String, default: "" },
    jazzcashAccountName: { type: String, default: "" },
    jazzcashAccountNumber: { type: String, default: "" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("AccountDetails", accountDetailsSchema);
