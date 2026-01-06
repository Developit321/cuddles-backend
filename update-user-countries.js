const mongoose = require("mongoose");
const { updateUsersWithNoCountry } = require("./Controllers/userController");

// MongoDB connection string
const MONGODB_URI =
  "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/";

async function runUpdateUserCountries() {
  try {
    // Connect to MongoDB
    console.log("🔌 Connecting to MongoDB...");
    await mongoose.connect(MONGODB_URI);
    console.log("✅ Connected to MongoDB\n");

    // Run the update function
    const result = await updateUsersWithNoCountry();

    // Display final results
    if (result.cancelled) {
      console.log("\n🚫 Update process was cancelled.");
    } else {
      console.log("\n🎉 Update process completed!");
      console.log(`✅ Updated: ${result.updated}`);
      console.log(`⏩ Skipped: ${result.skipped}`);
      console.log(`❌ Failed: ${result.failed}`);
    }
  } catch (error) {
    console.error("❌ Error running update:", error);
  } finally {
    await mongoose.disconnect();
    console.log("\n🔌 Disconnected from MongoDB");
    process.exit(0); // Exit the process
  }
}

runUpdateUserCountries();









