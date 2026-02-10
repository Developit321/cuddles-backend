const mongoose = require("mongoose");

mongoose.set("strictPopulate", false);

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: false,
    },
    age: {
      type: String,
      required: false,
    },
    gender: {
      type: String,
      enum: ["male", "female", "other"],
    },
    preferences: {
      type: String,
      enum: ["male", "female", "Non-Binary", "all", "non-binary"],
    },
    verified: {
      type: Boolean,
      default: false,
    },
    VerificationToken: {
      type: String,
    },
    profileVerification: {
      selfieUrl: {
        type: String,
        default: null,
      },
      status: {
        type: String,
        enum: ["pending", "approved", "rejected"],
        default: "pending",
      },
      submittedAt: {
        type: Date,
        default: null,
      },
      reviewedAt: {
        type: Date,
        default: null,
      },
      reviewedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null,
      },
      notes: {
        type: String,
        default: "",
      },
    },
    crushes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    recievedLikes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    profileDislikes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    blockedBy: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    Matches: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    profileImages: {
      type: [String],
      default: [],
    },
    description: {
      type: String,
    },
    pushToken: {
      type: String,
    },
    platform: {
      type: String,
      enum: ["ios", "android", "unknown"],
      default: "unknown",
    },
    interests: {
      type: [String],
      default: [],
    },
    lookingFor: {
      type: [String],
      enum: ["Friendship", "Goodtime", "Long term relationship"],
      default: [],
    },
    otp: {
      code: {
        type: String,
        required: false,
      },
      expires: {
        type: Date,
        required: false,
      },
    },
    location: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point",
        required: false,
      },
      coordinates: {
        type: [Number],
        required: false,
        default: [0, 0],
      },
      country: {
        // Add this field
        type: String,
        required: false,
      },
    },
    conversations: [
      {
        receiverId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        unreadMessagesCount: { type: Number, default: 0 },
      },
    ],
    dailyQuestion: {
      question: { type: String },
      answer: { type: String },
      answeredAt: { type: Date },
    },
    priority: { type: Number, default: 0 },
    availability: {
      type: [String],
      enum: ["morning", "afternoon", "evening"],
      default: [],
    },
    expectations: {
      type: [String],
      default: [],
    },
    anonymous: {
      type: Boolean,
      default: false,
    },
    flagged: {
      type: Boolean,
      default: false,
    },
    flagReason: {
      type: String,
      default: "",
    },
    lastNotificationSent: {
      type: Date,
      default: null,
    },
    lastActiveAt: {
      type: Date,
      default: null,
    },
    showInOpenTab: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
); // Add timestamps option here

// Create only one 2dsphere index for geospatial queries
userSchema.index({ location: "2dsphere" });

// Add additional indexes for frequently queried fields
userSchema.index({ gender: 1, age: 1 });
userSchema.index({ priority: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ updatedAt: -1 });
userSchema.index({ lastActiveAt: -1 });

// Compound indexes for optimized profile and nearby-users queries
userSchema.index({ "location.country": 1, gender: 1, flagged: 1 });
userSchema.index({ flagged: 1, anonymous: 1 });
userSchema.index({ lastActiveAt: -1, flagged: 1, anonymous: 1 });

// Index for nearby-users query optimization (supports $geoNear filter)
userSchema.index({ flagged: 1, profileImages: 1 });

const User = mongoose.model("User", userSchema);

module.exports = User;
