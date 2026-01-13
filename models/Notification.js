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
    ],
    required: true,
  },
  title: { type: String, required: true },
  message: { type: String, required: true },
  eventId: { type: mongoose.Schema.Types.ObjectId, ref: "Event" },
  eventName: String,
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  actorName: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, index: true },
});

// Compound index for efficient queries
notificationSchema.index({ userId: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, read: 1 });

module.exports = mongoose.model("Notification", notificationSchema);

