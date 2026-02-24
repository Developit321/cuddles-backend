const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema({
  reporterId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  reportedUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  reportedEventId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Event",
  },
  reason: {
    type: String,
    enum: ["fake_profile", "harassment", "scam", "offensive_content", "no_show", "other"],
  },
  message: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  status: {
    type: String,
    enum: ["pending", "resolved"],
    default: "pending",
  },
  action: {
    type: String,
    enum: ["dismiss", "warn", "block"],
  },
  notes: {
    type: String,
  },
  resolvedAt: {
    type: Date,
  },
});

const Report = mongoose.model("Report", reportSchema);
module.exports = Report;
