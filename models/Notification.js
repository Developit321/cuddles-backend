const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  type: {
    type: String,
    enum: [
      "event_joined",
      "event_reminder",
      "event_nearby",
      "event_cancelled",
      "event_updated",
      "event_checkin",
      "event_removed",
      "table_60_full",
      "table_filling_fast",
      "rate_host",
      "profile_like",
      "super_wave",
      "activity_suggestion",
      "suggestion_accepted",
      "suggestion_declined",
      "suggestion_expired",
      "boost_activated",
      "boost_warning",
      "boost_expired",
      "boost_credits_reset",
      "after_rating",
      "host_third_rating",
      "capetown_weekend",
      "event_join_request",
      "event_join_request_rejected",
    ],
    required: true,
  },
  category: {
    type: String,
    enum: ["transactional", "discovery", "fomo", "re_engagement", "post_experience"],
    default: null,
  },
  title: { type: String, required: true },
  message: { type: String, required: true },
  eventId: { type: mongoose.Schema.Types.ObjectId, ref: "Event" },
  eventName: String,
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  actorName: String,
  actorImage: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, index: true },
});

// Compound index for efficient queries
notificationSchema.index({ userId: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, read: 1 });
notificationSchema.index({ userId: 1, category: 1, createdAt: -1 });

module.exports = mongoose.model("Notification", notificationSchema);

