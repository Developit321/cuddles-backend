// TEMP: pitch-vote — safe to delete after event
const mongoose = require("mongoose");

const pitchVotePitcherSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    photoUrl: { type: String, required: true, trim: true },
    privateToken: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PitchVotePitcher", pitchVotePitcherSchema);
