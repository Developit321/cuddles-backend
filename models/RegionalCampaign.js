const mongoose = require("mongoose");

const regionalCampaignSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    status: {
      type: String,
      enum: ["draft", "scheduled", "running", "completed", "failed", "paused", "cancelled"],
      default: "draft",
      index: true,
    },
    regionType: {
      type: String,
      enum: ["country", "radius", "country_plus_radius"],
      required: true,
    },
    country: { type: String, default: null, trim: true },
    center: {
      lng: { type: Number, default: null },
      lat: { type: Number, default: null },
    },
    radiusM: { type: Number, default: null },
    notificationType: { type: String, default: "capetown_weekend" },
    title: { type: String, required: true },
    message: { type: String, required: true },
    timezone: { type: String, default: "UTC" },
    scheduleAt: { type: Date, default: null, index: true },
    requirePushToken: { type: Boolean, default: true },
    eventsOnly: { type: Boolean, default: true },
    audience: {
      gender: { type: String, enum: ["male", "female", "other"], default: null },
      minLastActiveDays: { type: Number, default: null },
    },
    metrics: {
      targetedCount: { type: Number, default: 0 },
      eligibleCount: { type: Number, default: 0 },
      sentCount: { type: Number, default: 0 },
      skippedCapCount: { type: Number, default: 0 },
      invalidTokenCount: { type: Number, default: 0 },
      failedCount: { type: Number, default: 0 },
    },
    lastRunAt: { type: Date, default: null },
    lastError: { type: String, default: "" },
  },
  { timestamps: true }
);

regionalCampaignSchema.index({ createdAt: -1, status: 1 });
regionalCampaignSchema.index({ regionType: 1, country: 1 });

module.exports = mongoose.model("RegionalCampaign", regionalCampaignSchema);
