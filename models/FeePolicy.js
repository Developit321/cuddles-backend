const mongoose = require("mongoose");

const feePolicySchema = new mongoose.Schema(
  {
    singletonKey: {
      type: String,
      required: true,
      unique: true,
      default: "default",
    },
    appFeeType: {
      type: String,
      enum: ["percentage", "flat", "hybrid"],
      default: "percentage",
    },
    appFeeValue: { type: Number, default: 10, min: 0 },
    appFeeFlatAmount: { type: Number, default: 0, min: 0 },
    processingFeeMode: {
      type: String,
      enum: ["platform", "host", "buyer"],
      default: "buyer",
    },
    minFeeAmount: { type: Number, default: 0, min: 0 },
    maxFeeAmount: { type: Number, default: 0, min: 0 },
    taxRatePercent: { type: Number, default: 0, min: 0 },
    isActive: { type: Boolean, default: true },
    effectiveFrom: { type: Date, default: Date.now },
    metadata: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("FeePolicy", feePolicySchema);
