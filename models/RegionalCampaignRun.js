const mongoose = require("mongoose");

const regionalCampaignRunSchema = new mongoose.Schema(
  {
    campaignId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "RegionalCampaign",
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["running", "completed", "failed", "cancelled"],
      default: "running",
      index: true,
    },
    startedAt: { type: Date, default: Date.now, index: true },
    finishedAt: { type: Date, default: null },
    metrics: {
      targetedCount: { type: Number, default: 0 },
      eligibleCount: { type: Number, default: 0 },
      sentCount: { type: Number, default: 0 },
      skippedCapCount: { type: Number, default: 0 },
      invalidTokenCount: { type: Number, default: 0 },
      failedCount: { type: Number, default: 0 },
    },
    errorSummary: { type: String, default: "" },
  },
  { timestamps: true }
);

regionalCampaignRunSchema.index({ campaignId: 1, createdAt: -1 });

module.exports = mongoose.model("RegionalCampaignRun", regionalCampaignRunSchema);
