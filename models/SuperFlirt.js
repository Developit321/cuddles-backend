const mongoose = require("mongoose");

const superFlirtSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    message: {
      type: String,
      required: true,
      maxlength: 150,
    },
    status: {
      type: String,
      enum: ["pending", "matched", "passed"],
      default: "pending",
    },
  },
  { timestamps: true }
);

superFlirtSchema.index({ receiverId: 1, status: 1 });
superFlirtSchema.index({ senderId: 1 });

const SuperFlirt = mongoose.model("SuperFlirt", superFlirtSchema);
module.exports = SuperFlirt;
