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
const User = mongoose.model("User", userSchema);

module.exports = User;
