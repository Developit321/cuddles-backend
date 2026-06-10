const mongoose = require("mongoose");

const DIETARY_PIZZA_OPTIONS = ["vegetarian", "vegan", "glutenFree", "other"];

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
