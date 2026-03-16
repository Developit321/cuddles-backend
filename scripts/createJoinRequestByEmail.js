const mongoose = require("mongoose");
const axios = require("axios");
const Event = require("../models/Event");

async function main() {
  const EVENT_ID = process.env.EVENT_ID || "69b7e92f33649b44919d0f62";
  const USER_ID = process.env.USER_ID || "69b7f18a21887eef215d1574";
  // Default BASE_URL to the same host the client uses in eventApi.js
  const BASE_URL =
    process.env.BASE_URL || "https://cuddles-batcat.onrender.com";
  const STATUS = process.env.JOIN_STATUS || "interested"; // matches client default

  if (!EVENT_ID || !USER_ID) {
    console.error(
      "Please set EVENT_ID and USER_ID environment variables (and optionally BASE_URL, JOIN_STATUS).",
    );
    process.exit(1);
  }

  try {
    console.log("Connecting to MongoDB to verify event...");
    await mongoose.connect(
      "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      },
    );

    const event = await Event.findById(EVENT_ID).select("title").lean();
    if (!event) {
      console.error(`No event found for id: ${EVENT_ID}`);
      process.exit(1);
    }

    console.log(
      `Calling real join API for userId=${USER_ID}, event="${event.title}" (${EVENT_ID}), status="${STATUS}"`,
    );

    const res = await axios.post(`${BASE_URL}/events/${EVENT_ID}/join`, {
      userId: USER_ID,
      status: STATUS,
    });

    console.log("Response from /events/:eventId/join:");
    console.log(res.data);
  } catch (err) {
    if (err.response) {
      console.error(
        "API error:",
        err.response.status,
        JSON.stringify(err.response.data, null, 2),
      );
    } else {
      console.error("Error:", err.message);
    }
  } finally {
    await mongoose.disconnect().catch(() => {});
  }
}

main();
