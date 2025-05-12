const mongoose = require("mongoose");

const chatSchema = new mongoose.Schema({
  senderId: {
    type: String,
    required: true,
  },
  receiverId: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: function () {
      return this.type !== "image";
    },
  },
  type: {
    type: String,
    enum: ["text", "image"],
    default: "text",
  },
  image: {
    type: String, // This will store the base64 image data
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  read: {
    type: Boolean,
    default: false,
  },
});

const Chat = mongoose.model("Chat", chatSchema);
module.exports = Chat;
