const mongoose = require("mongoose");

const groupMessageSchema = new mongoose.Schema({
  groupName: {
    type: String,
    required: true,
    enum: ["Good Times", "Vibes", "Friendships"], // Restrict to the three groups
  },
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  readBy: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  ],
});

const GroupMessage = mongoose.model("GroupMessage", groupMessageSchema);

module.exports = GroupMessage;
