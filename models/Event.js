const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema(
  {
    hostId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    title: {
      type: String,
      required: true,
      maxlength: 100,
    },
    description: {
      type: String,
      maxlength: 500,
    },
    location: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point",
      },
      coordinates: {
        type: [Number],
        required: true, // [longitude, latitude]
      },
      name: {
        type: String,
        required: true, // e.g., "Downtown Café"
      },
      address: {
        type: String,
      },
    },
    coverImage: {
      type: String, // Cloudinary URL
    },
    startTime: {
      type: Date,
      required: true,
    },
    endTime: {
      type: Date,
    },
    capacity: {
      type: Number,
      default: 6,
      max: 6,
    },
    participants: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        status: {
          type: String,
          enum: ["interested", "going", "checked_in"],
          default: "interested",
        },
        joinedAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    status: {
      type: String,
      enum: ["upcoming", "live", "full", "ended", "cancelled"],
      default: "upcoming",
    },
    tags: [
      {
        type: String,
      },
    ],
    checkInRadius: {
      type: Number,
      default: 100, // meters
    },
    reminderSent: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// Indexes for efficient queries
eventSchema.index({ location: "2dsphere" });
eventSchema.index({ status: 1, startTime: 1 });
eventSchema.index({ tags: 1 });
eventSchema.index({ hostId: 1 });
eventSchema.index({ "participants.userId": 1 });

const Event = mongoose.model("Event", eventSchema);
module.exports = Event;










