const mongoose = require("mongoose");
const Question = require("../models/ Question");
require("../index"); // Import your index.js file to initiate the connection

const questions = [
  {
    question: "What’s your biggest turn-on?",
    options: ["A seductive voice", "Good chemistry", "Physical touch"],
  },
  {
    question: "What’s your favorite part of foreplay?",
    options: ["Kissing", "Teasing", "Whispers and compliments"],
  },
  {
    question: "Would you rather experiment in the bedroom or keep it simple?",
    options: ["Experiment", "Keep it simple", "Depends on the mood"],
  },
  {
    question: "What’s your favorite spot to be kissed?",
    options: ["Neck", "Lips", "Everywhere"],
  },
  {
    question: "Do you prefer slow and sensual or wild and passionate?",
    options: ["Slow and sensual", "Wild and passionate", "Both!"],
  },
  {
    question: "What’s the most daring place you’ve been intimate?",
    options: ["Car", "Beach", "Secret location"],
  },
  {
    question: "What’s one thing you’ve always wanted to try but haven’t yet?",
    options: ["Roleplay", "Using toys", "Something taboo"],
  },
  {
    question: "What’s your favorite time of day for intimacy?",
    options: ["Morning", "Night", "Whenever the moment strikes"],
  },
  {
    question: "Would you rather be in control or let your partner take charge?",
    options: ["In control", "Partner in control", "Switch it up"],
  },
  {
    question: "What’s your favorite type of lingerie (or to see on a partner)?",
    options: ["Lacy and sexy", "Simple and elegant", "Nothing at all"],
  },
  {
    question: "Do you enjoy dirty talk?",
    options: ["Yes, it’s exciting", "Sometimes", "Not really my thing"],
  },
  {
    question: "What’s your favorite position?",
    options: ["Classic missionary", "Adventurous", "Something unique"],
  },
  {
    question: "Do you prefer lights on or off during intimacy?",
    options: ["On", "Off", "Mood lighting"],
  },
  {
    question: "What’s your favorite way to spice things up?",
    options: [
      "Trying new positions",
      "Watching something steamy together",
      "Dressing up",
    ],
  },
  {
    question: "Do you enjoy giving or receiving massages?",
    options: ["Giving", "Receiving", "Both!"],
  },
  {
    question:
      "Have you ever sent or received a flirty text that got out of hand?",
    options: ["Yes, it was thrilling", "No, but I’d like to", "Not my thing"],
  },
  {
    question: "What’s your secret move in the bedroom?",
    options: ["A perfect kiss", "Slow teasing", "Keeping it spontaneous"],
  },
  {
    question: "Do you believe in love or lust at first sight?",
    options: ["Love", "Lust", "A bit of both"],
  },
];

const seedQuestions = async () => {
  try {
    // Clear existing questions
    // await Question.deleteMany();

    // Insert new questions
    await Question.insertMany(questions);

    console.log("Questions seeded successfully!");
  } catch (error) {
    console.error("Error seeding questions:", error);
  } finally {
    // Close the connection after seeding
    mongoose.connection.close();
  }
};

// Run the seeder
seedQuestions();
