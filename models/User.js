const mongoose = require("mongoose");

mongoose.set("strictPopulate", false);

const userSchema = mongoose.Schema({
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
    required: true,
  },
  age: {
    type: String,
    required: false,
  },
  gender: {
    type: String,
    enum: ["male", "female", "other"],
  },

  verified: {
    type: Boolean,
    default: false,
  },
  VerificatiionToken: String,
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
  location: {
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
  VerificationToken: {
    type: String,
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
      required: false,
    },
    coordinates: {
      type: [Number],
      required: false,
      index: "2dsphere",
    },
  },
});
userSchema.index({ location: "2dsphere" });
const User = mongoose.model("User", userSchema);

module.exports = User;
