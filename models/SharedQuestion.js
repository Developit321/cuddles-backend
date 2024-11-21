const mongoose = require("mongoose");

const sharedQuestionSchema = new mongoose.Schema({
  date: { type: Date, default: Date.now },
  questionId: { type: mongoose.Schema.Types.ObjectId, ref: "Question" },
});

const SharedQuestion = mongoose.model("SharedQuestion", sharedQuestionSchema);

module.exports = SharedQuestion; // Make sure you're exporting the model
