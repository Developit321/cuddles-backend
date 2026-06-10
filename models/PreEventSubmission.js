const mongoose = require("mongoose");

const DIETARY_PIZZA_OPTIONS = ["vegetarian", "vegan", "glutenFree", "other"];

const ROOM_PRESENCE_OPTIONS = [
  "quietObserver",
  "warmAndChatty",
  "takesCharge",
  "playfulAndLight",
  "thoughtfulAndMeasured",
];

const ACTING_COMFORT_OPTIONS = ["low", "moderate", "confident", "veryConfident"];

const DRINKS_PREFERENCE_OPTIONS = ["none", "red", "white"];

const DISCOMFORT_TOPIC_OPTIONS = [
  "killer",
  "villain",
  "flirtatious",
  "romantic",
  "morallyDark",
  "chronicLiar",
  "other",
];

const preEventSubmissionSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    favouriteCharacterId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PreEventCharacter",
      default: null,
    },
    avoidCharacterId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PreEventCharacter",
      default: null,
    },
    roomPresence: {
      type: String,
      enum: [...ROOM_PRESENCE_OPTIONS, null],
      default: null,
    },
    actingComfort: {
      type: String,
      enum: [...ACTING_COMFORT_OPTIONS, null],
      default: null,
    },
    discomfortTopics: {
      type: [String],
      enum: DISCOMFORT_TOPIC_OPTIONS,
      default: [],
    },
    discomfortOther: {
      type: String,
      default: "",
      trim: true,
      maxlength: 200,
    },
    castingNotes: {
      type: String,
      default: "",
      trim: true,
      maxlength: 500,
    },
    dietaryPizza: {
      type: [String],
      enum: DIETARY_PIZZA_OPTIONS,
      default: [],
    },
    dietaryPizzaOther: {
      type: String,
      default: "",
      trim: true,
      maxlength: 200,
    },
    drinksPreference: {
      type: String,
      enum: [...DRINKS_PREFERENCE_OPTIONS, null],
      default: null,
    },
    drinksWine: {
      type: Boolean,
      default: null,
    },
    submittedAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: false },
);

module.exports = mongoose.model("PreEventSubmission", preEventSubmissionSchema);
module.exports.DIETARY_PIZZA_OPTIONS = DIETARY_PIZZA_OPTIONS;
module.exports.ROOM_PRESENCE_OPTIONS = ROOM_PRESENCE_OPTIONS;
module.exports.ACTING_COMFORT_OPTIONS = ACTING_COMFORT_OPTIONS;
module.exports.DISCOMFORT_TOPIC_OPTIONS = DISCOMFORT_TOPIC_OPTIONS;
module.exports.DRINKS_PREFERENCE_OPTIONS = DRINKS_PREFERENCE_OPTIONS;
