// TEMP: pitch-vote — safe to delete after event
const mongoose = require("mongoose");

const pitchVoteVoterSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    photoUrl: { type: String, required: true, trim: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PitchVoteVoter", pitchVoteVoterSchema);
