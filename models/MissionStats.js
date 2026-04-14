const mongoose = require("mongoose");

const missionStatsSchema = new mongoose.Schema(
  {
    singletonKey: {
      type: String,
      required: true,
      unique: true,
      default: "global",
    },
    tablesCreatedTotal: {
      type: Number,
      default: 0,
    },
    strangersConnectedTotal: {
      type: Number,
      default: 0,
    },
    goal: {
      type: Number,
      default: 1000000,
    },
  },
  { timestamps: true }
);

const MissionStats = mongoose.model("MissionStats", missionStatsSchema);
module.exports = MissionStats;
