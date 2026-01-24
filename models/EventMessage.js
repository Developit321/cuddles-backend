const mongoose = require("mongoose");

const eventMessageSchema = new mongoose.Schema({
  eventId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Event",
    required: true,
  },
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  message: {
    type: String,
  },
  type: {
    type: String,
    enum: ["text", "image", "system"],
    default: "text",
  },
  image: {
    type: String, // Cloudinary URL for image messages
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Index for efficient message retrieval by event
eventMessageSchema.index({ eventId: 1, createdAt: -1 });

const EventMessage = mongoose.model("EventMessage", eventMessageSchema);
module.exports = EventMessage;












