const mongoose = require("mongoose");

const buttonLinksSchema = new mongoose.Schema(
  {
    linkOne: { type: String, default: "" },
    linkTwo: { type: String, default: "" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("ButtonLinks", buttonLinksSchema);
