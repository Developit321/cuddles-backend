const mongoose = require("mongoose");
const Event = require("../models/Event");

const mongoUri =
  process.env.MONGO_URI ||
  "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/";

const parseHostIds = (value) =>
  String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

async function main() {
  const invitableHostIds = parseHostIds(process.env.INVITABLE_HOST_IDS);
  const isDryRun = process.env.DRY_RUN === "1";

  try {
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to MongoDB");

    const existingOrganizerTypeCount = await Event.countDocuments({
      organizerType: { $exists: true },
    });
    console.log("Events with organizerType already set:", existingOrganizerTypeCount);

    if (isDryRun) {
      const missingCount = await Event.countDocuments({
        organizerType: { $exists: false },
      });
      const invitableCount = invitableHostIds.length
        ? await Event.countDocuments({
            hostId: { $in: invitableHostIds },
            organizerType: { $ne: "invitable" },
          })
        : 0;
      console.log("DRY_RUN=1, no writes performed");
      console.log("Would set organizerType=user for events missing field:", missingCount);
      console.log(
        "Would set organizerType=invitable for configured host IDs:",
        invitableCount,
      );
      return;
    }

    const baseUpdate = await Event.updateMany(
      { organizerType: { $exists: false } },
      { $set: { organizerType: "user" } },
    );
    console.log(
      "Backfilled organizerType=user for events:",
      baseUpdate.modifiedCount || 0,
    );

    if (invitableHostIds.length > 0) {
      const invitableUpdate = await Event.updateMany(
        { hostId: { $in: invitableHostIds } },
        { $set: { organizerType: "invitable" } },
      );
      console.log(
        "Updated organizerType=invitable for host IDs:",
        invitableUpdate.modifiedCount || 0,
      );
    } else {
      console.log(
        "No INVITABLE_HOST_IDS provided; skipped invitable host tagging step.",
      );
    }
  } catch (error) {
    console.error("Backfill failed:", error);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  }
}

main();
