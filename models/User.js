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
    required: true,
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

  interests: {
    type: [String], // Array of strings
    default: [],
  },

  lookingFor: {
    type: [String],
    default: [],
  },
  VerificationToken: {
    type: String,
  },
  profilePicture: {
    filename: String,
    path: String,
    mimetype: String,
    size: Number,
  },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
