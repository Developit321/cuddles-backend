const mongoose = require("mongoose");

const boostSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    activatedAt: {
      type: Date,
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    status: {
      type: String,
      enum: ["active", "expired"],
      default: "active",
    },
    warningNotifSent: {
      type: Boolean,
      default: false,
    },
    expiryNotifSent: {
      type: Boolean,
      default: false,
    },
    impressionCount: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

boostSchema.index({ userId: 1, status: 1 });
boostSchema.index({ expiresAt: 1, status: 1 });
boostSchema.index({ activatedAt: 1, status: 1 });

const Boost = mongoose.model("Boost", boostSchema);
module.exports = Boost;
