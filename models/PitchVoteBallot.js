// TEMP: pitch-vote — safe to delete after event
const mongoose = require("mongoose");

const pitchVoteBallotSchema = new mongoose.Schema(
  {
    pitcherId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PitchVotePitcher",
      required: true,
      index: true,
    },
    voterName: { type: String, required: true, trim: true, maxlength: 80 },
    voterPhotoUrl: { type: String, required: true, trim: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PitchVoteBallot", pitchVoteBallotSchema);
