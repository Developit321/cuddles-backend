const User = require("../models/User"); // Use require to import User model
const NodeGeocoder = require("node-geocoder");

// Initialize the geocoder with OpenStreetMap with better configuration
const geocoder = NodeGeocoder({
  provider: "openstreetmap",
  httpAdapter: "https",
  formatter: null,
  timeout: 5000,
  headers: {
    "User-Agent": "Cuddles-App/1.0.4", // Add user agent to avoid rate limiting
  },
});

const checkIfAnsweredToday = async (userId) => {
  const now = new Date();
  const startOfDay = new Date(now.setHours(0, 0, 0, 0));
  const endOfDay = new Date(now.setHours(23, 59, 59, 999));

  try {
    const user = await User.findById(userId); // Use User model to find the user by ID
    if (!user) {
      return false;
    }

    const answeredToday =
      user.dailyQuestion.answeredAt >= startOfDay &&
      user.dailyQuestion.answeredAt <= endOfDay;
    return answeredToday;
  } catch (error) {
    console.error("Error checking if user answered today:", error);
    return false;
  }
};

// Function to update country for a single user based on their coordinates
const updateUserCountry = async (userId) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      console.log(`❌ User not found: ${userId}`);
      throw new Error("User not found");
    }

    // Check if user has valid coordinates
    if (
      !user.location?.coordinates ||
      !Array.isArray(user.location.coordinates) ||
      user.location.coordinates.length !== 2 ||
      (user.location.coordinates[0] === 0 && user.location.coordinates[1] === 0)
    ) {
      console.log(
        `⚠️ Invalid coordinates for user ${userId}: ${JSON.stringify(
          user.location?.coordinates
        )}`
      );
      throw new Error("User has no valid coordinates");
    }

    const [longitude, latitude] = user.location.coordinates;

    // Validate coordinates are within reasonable bounds
    if (Math.abs(latitude) > 90 || Math.abs(longitude) > 180) {
      console.log(`❌ Coordinates out of bounds: [${latitude}, ${longitude}]`);
      throw new Error("Coordinates out of bounds");
    }

    console.log(
      `🌍 Processing user ${userId} - Coordinates: [${latitude}, ${longitude}]`
    );

    // Add retry logic for geocoding
    let retries = 3;
    let geoData = null;
    let error = null;

    while (retries > 0 && !geoData) {
      try {
        // Note: Nominatim expects lat,lon order
        geoData = await geocoder.reverse({ lat: latitude, lon: longitude });
        break;
      } catch (err) {
        error = err;
        retries--;
        if (retries > 0) {
          // Wait before retrying (exponential backoff)
          await new Promise((resolve) =>
            setTimeout(resolve, (3 - retries) * 1000)
          );
        }
      }
    }

    if (!geoData && error) {
      console.error("Failed all retry attempts:", error);
      throw error;
    }

    if (geoData && geoData[0] && geoData[0].country) {
      // Update the user's country
      user.location.country = geoData[0].country;
      await user.save();

      console.log(`✅ Updated user ${userId} - Country: ${geoData[0].country}`);
      return {
        success: true,
        message: "Country updated successfully",
        country: geoData[0].country,
        userId: user._id,
      };
    } else {
      console.log(
        `❌ Could not determine country for coordinates [${latitude}, ${longitude}]`
      );
      throw new Error("Could not determine country from coordinates");
    }
  } catch (error) {
    console.error("Error updating user country:", error);
    throw error;
  }
};

// Function to update countries for all users with valid coordinates
const updateAllUsersCountries = async () => {
  try {
    console.log("\n🔄 Starting country update process...");

    // Find all users that have location object with non-default coordinates
    const users = await User.find({
      "location.coordinates": {
        $exists: true,
        $ne: [0, 0],
        $type: "array",
        $size: 2,
      },
    });

    console.log(`📊 Found ${users.length} users with coordinates`);

    const results = {
      total: users.length,
      updated: 0,
      skipped: 0,
      failed: 0,
      details: [],
    };

    let processedCount = 0;
    for (const user of users) {
      processedCount++;
      console.log(
        `\n👤 Processing user ${processedCount}/${users.length} (${(
          (processedCount / users.length) *
          100
        ).toFixed(1)}%)`
      );

      try {
        // Additional validation check for coordinates
        if (
          !user.location?.coordinates ||
          !Array.isArray(user.location.coordinates) ||
          user.location.coordinates.length !== 2 ||
          (user.location.coordinates[0] === 0 &&
            user.location.coordinates[1] === 0)
        ) {
          console.log(
            `⏩ Skipping user ${
              user._id
            } - Invalid coordinates: ${JSON.stringify(
              user.location?.coordinates
            )}`
          );
          results.skipped++;
          results.details.push({
            userId: user._id,
            status: "skipped",
            reason: "Invalid or missing coordinates",
          });
          continue;
        }

        const result = await updateUserCountry(user._id);
        results.updated++;
        results.details.push({
          userId: user._id,
          status: "success",
          country: result.country,
        });
      } catch (error) {
        console.log(`❌ Failed to update user ${user._id}: ${error.message}`);
        results.failed++;
        results.details.push({
          userId: user._id,
          status: "failed",
          error: error.message,
        });
      }
    }

    const summary = `\n📈 Final Results:
    Total Processed: ${results.total}
    ✅ Successfully Updated: ${results.updated}
    ⏩ Skipped: ${results.skipped}
    ❌ Failed: ${results.failed}
    Success Rate: ${((results.updated / results.total) * 100).toFixed(1)}%`;

    console.log(summary);

    return {
      ...results,
      summary,
    };
  } catch (error) {
    console.error("❌ Error updating all users countries:", error);
    throw error;
  }
};

// Initial call to update all users' countries

module.exports = {
  checkIfAnsweredToday,
  updateUserCountry,
  updateAllUsersCountries,
}; // Export the function using CommonJS
