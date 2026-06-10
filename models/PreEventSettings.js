const mongoose = require("mongoose");

const preEventSettingsSchema = new mongoose.Schema(
  {
    locked: {
      type: Boolean,
      default: false,
    },
    lockedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true },
);

module.exports = mongoose.model("PreEventSettings", preEventSettingsSchema);
