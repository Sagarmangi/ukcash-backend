const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: [
      "deposit",
      "withdraw",
      "account creation",
      "account approval",
      "role change",
      "submission update",
      "submission deleted",
    ],
    required: true,
  },
  notification: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("Notification", notificationSchema);
