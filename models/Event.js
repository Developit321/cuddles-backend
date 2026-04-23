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
      max: 10,
    },
    requiresApproval: {
      type: Boolean,
      default: false,
    },
    isPaid: {
      type: Boolean,
      default: false,
    },
    priceAmount: {
      type: Number,
      min: 0,
      default: 0,
    },
    currency: {
      type: String,
      default: "ZAR",
      uppercase: true,
      trim: true,
    },
    paymentPolicy: {
      type: String,
      enum: ["pay_before_join", "pay_after_approval"],
      default: "pay_before_join",
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
    joinRequests: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    waitlist: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    status: {
      type: String,
      enum: ["upcoming", "live", "full", "ended", "cancelled", "suggested"],
      default: "upcoming",
    },
    suggestedToUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    suggestedToUserIds: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    }],
    expiresAt: {
      type: Date,
    },
    tags: [
      {
        type: String,
      },
    ],
    audience: {
      type: String,
      enum: ["everyone", "women_only", "men_only"],
      default: "everyone",
    },
    checkInRadius: {
      type: Number,
      default: 100, // meters
    },
    reminderSent: {
      type: Boolean,
      default: false,
    },
    ratingReminderSent: {
      type: Boolean,
      default: false,
    },
    sixtyPercentNotifSent: {
      type: Boolean,
      default: false,
    },
    missionStatsCounted: {
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










