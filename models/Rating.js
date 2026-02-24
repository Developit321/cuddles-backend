const mongoose = require("mongoose");

const ratingSchema = new mongoose.Schema(
  {
    eventId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Event",
      required: true,
    },
    raterId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    hostId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    stars: {
      type: Number,
      min: 1,
      max: 5,
      required: true,
    },
    tags: [
      {
        type: String,
        enum: [
          "friendly",
          "on_time",
          "safe",
          "good_communication",
          "as_described",
        ],
      },
    ],
  },
  { timestamps: true }
);

ratingSchema.index({ hostId: 1 });
ratingSchema.index({ eventId: 1, raterId: 1 }, { unique: true });

const Rating = mongoose.model("Rating", ratingSchema);
module.exports = Rating;
