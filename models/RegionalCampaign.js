const mongoose = require("mongoose");

const regionalCampaignSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    regionType: {
      type: String,
      enum: ["country", "radius", "country_plus_radius"],
      required: true,
    },
    country: { type: String, default: null },
    center: {
      type: { type: String, enum: ["Point"], default: "Point" },
      coordinates: { type: [Number], default: [0, 0] },
    },
    radiusM: { type: Number, default: null },
    title: { type: String, required: true },
    message: { type: String, required: true },
    timezone: { type: String, default: "UTC" },
    scheduleAt: { type: Date, default: null },
    status: {
      type: String,
      enum: ["draft", "scheduled", "running", "completed", "failed", "paused", "cancelled"],
      default: "draft",
    },
    eventsOnly: { type: Boolean, default: true },
    requirePushToken: { type: Boolean, default: true },
    audience: {
      gender: { type: String, default: null },
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
    testUser: { type: String, default: null },
    lastRunAt: { type: Date, default: null },
  },
  { timestamps: true }
);

regionalCampaignSchema.index({ status: 1, scheduleAt: 1 });

module.exports = mongoose.model("RegionalCampaign", regionalCampaignSchema);
