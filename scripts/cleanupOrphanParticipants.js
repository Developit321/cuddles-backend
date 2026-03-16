const mongoose = require("mongoose");
const Event = require("../models/Event");
const User = require("../models/User");

async function main() {
  try {
    await mongoose.connect(
      "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/",
      {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      }
    );
    console.log("Connected to MongoDB");

    const events = await Event.find({}, { "participants.userId": 1 }).lean();
    const idSet = new Set();

    for (const ev of events) {
      for (const p of ev.participants || []) {
        if (p.userId) {
          idSet.add(p.userId.toString());
        }
      }
    }

    const allParticipantIds = Array.from(idSet);
    console.log(`Found ${allParticipantIds.length} unique participant userIds`);

    if (allParticipantIds.length === 0) {
      console.log("No participants to clean. Exiting.");
      return;
    }

    const existingUsers = await User.find(
      { _id: { $in: allParticipantIds } },
      { _id: 1 }
    ).lean();
    const existingIdSet = new Set(existingUsers.map((u) => u._id.toString()));

    const missingIds = allParticipantIds.filter(
      (id) => !existingIdSet.has(id)
    );

    console.log(
      `Found ${missingIds.length} participant userIds with no existing User`
    );

    if (missingIds.length === 0) {
      console.log("No orphan participants found. Exiting.");
      return;
    }

    const result = await Event.updateMany(
      { "participants.userId": { $in: missingIds } },
      { $pull: { participants: { userId: { $in: missingIds } } } }
    );

    const matched =
      typeof result.matchedCount === "number"
        ? result.matchedCount
        : result.n || 0;
    const modified =
      typeof result.modifiedCount === "number"
        ? result.modifiedCount
        : result.nModified || 0;

    console.log(
      `Cleanup done. Matched ${matched} events, modified ${modified} events.`
    );
  } catch (err) {
    console.error("Cleanup failed:", err);
  } finally {
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  }
}

main();

