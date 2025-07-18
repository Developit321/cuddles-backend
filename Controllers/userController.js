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

// Function to update countries for users with coordinates but no country
const updateUsersWithNoCountry = async () => {
  try {
    console.log(
      "\n🔄 Starting country update process for users with no country..."
    );
    console.log("⏳ Querying database for users (newest first)...");

    // Find users that have valid coordinates but no country, sorted by creation date (newest first)
    const users = await User.find({
      "location.coordinates": {
        $exists: true,
        $ne: [0, 0],
        $type: "array",
        $size: 2,
      },
      $or: [
        { "location.country": { $exists: false } },
        { "location.country": null },
        { "location.country": "" },
      ],
    })
      .sort({ createdAt: -1 }) // Sort by creation date, newest first (-1 for descending order)
      .lean(); // Use lean() for better performance since we only need to read

    // Get total users count for comparison
    const totalUsersCount = await User.countDocuments();
    const usersWithCoordinates = await User.countDocuments({
      "location.coordinates": {
        $exists: true,
        $ne: [0, 0],
        $type: "array",
        $size: 2,
      },
    });
    const usersWithCountry = await User.countDocuments({
      "location.country": { $exists: true, $ne: null, $ne: "" },
    });

    console.log("\n📊 Database Statistics:");
    console.log(`Total Users in Database: ${totalUsersCount}`);
    console.log(`Users with Valid Coordinates: ${usersWithCoordinates}`);
    console.log(`Users with Country Set: ${usersWithCountry}`);
    console.log(`Users Needing Country Update: ${users.length}`);
    console.log("----------------------------------------");

    const results = {
      total: users.length,
      updated: 0,
      skipped: 0,
      failed: 0,
      details: [],
      countryStats: {},
      coordinateStats: {
        invalidFormat: 0,
        outOfBounds: 0,
        zeroCoordinates: 0,
      },
      dateRange:
        users.length > 0
          ? {
              newest: new Date(users[0].createdAt).toISOString(),
              oldest: new Date(users[users.length - 1].createdAt).toISOString(),
            }
          : null,
    };

    if (users.length === 0) {
      console.log("✨ No users found needing country updates!");
      return {
        ...results,
        databaseStats: {
          totalUsers: totalUsersCount,
          usersWithCoordinates,
          usersWithCountry,
        },
      };
    }

    console.log(
      `\n🚀 Beginning processing of ${users.length} users (newest to oldest)...`
    );
    console.log(
      `📅 Date Range: ${results.dateRange.newest} to ${results.dateRange.oldest}\n`
    );

    let processedCount = 0;
    const startTime = Date.now();

    for (const user of users) {
      processedCount++;
      const processingStart = Date.now();

      console.log(
        `\n👤 User ${processedCount}/${users.length} (${(
          (processedCount / users.length) *
          100
        ).toFixed(1)}%)`
      );
      console.log(`ID: ${user._id}`);
      console.log(`Created: ${new Date(user.createdAt).toISOString()}`);
      console.log(`Coordinates: [${user.location.coordinates.join(", ")}]`);

      try {
        // Validate coordinates
        const [longitude, latitude] = user.location.coordinates;

        // Skip if coordinates are invalid
        if (Math.abs(latitude) > 90 || Math.abs(longitude) > 180) {
          console.log(
            `⚠️ Coordinates out of bounds: [${latitude}, ${longitude}]`
          );
          results.skipped++;
          results.coordinateStats.outOfBounds++;
          results.details.push({
            userId: user._id,
            createdAt: user.createdAt,
            status: "skipped",
            reason: "Coordinates out of bounds",
            coordinates: [longitude, latitude],
          });
          continue;
        }

        console.log(
          `🌍 Attempting to get country for coordinates: [${latitude}, ${longitude}]`
        );
        const result = await updateUserCountry(user._id);

        // Track successful updates
        results.updated++;
        results.countryStats[result.country] =
          (results.countryStats[result.country] || 0) + 1;

        const processingTime = Date.now() - processingStart;
        console.log(`✅ Success! Country found: ${result.country}`);
        console.log(`⏱️ Processing time: ${processingTime}ms`);

        results.details.push({
          userId: user._id,
          createdAt: user.createdAt,
          status: "success",
          country: result.country,
          coordinates: user.location.coordinates,
          processingTime,
        });

        // Add delay to avoid rate limiting
        if (processedCount < users.length) {
          console.log("⏳ Waiting 1s before next user...");
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      } catch (error) {
        const processingTime = Date.now() - processingStart;
        console.log(`❌ Failed: ${error.message}`);
        console.log(`⏱️ Processing time until failure: ${processingTime}ms`);

        results.failed++;
        results.details.push({
          userId: user._id,
          createdAt: user.createdAt,
          status: "failed",
          error: error.message,
          coordinates: user.location.coordinates,
          processingTime,
        });
      }
    }

    const totalTime = Date.now() - startTime;
    const averageTimePerUser = totalTime / users.length;

    const summary = `
📈 Final Results:
----------------------------------------
Total Users Processed: ${results.total}
✅ Successfully Updated: ${results.updated}
⏩ Skipped: ${results.skipped}
❌ Failed: ${results.failed}
Success Rate: ${((results.updated / results.total) * 100).toFixed(1)}%

📅 Date Range:
Newest User: ${results.dateRange.newest}
Oldest User: ${results.dateRange.oldest}

⏱️ Time Statistics:
Total Processing Time: ${(totalTime / 1000).toFixed(2)}s
Average Time per User: ${averageTimePerUser.toFixed(2)}ms

🌍 Country Distribution:
${Object.entries(results.countryStats)
  .sort(([, a], [, b]) => b - a)
  .map(([country, count]) => `${country}: ${count} users`)
  .join("\n")}

🎯 Coordinate Statistics:
Invalid Format: ${results.coordinateStats.invalidFormat}
Out of Bounds: ${results.coordinateStats.outOfBounds}
Zero Coordinates: ${results.coordinateStats.zeroCoordinates}

📊 Database Statistics:
Total Users: ${totalUsersCount}
Users with Coordinates: ${usersWithCoordinates}
Users with Country: ${usersWithCountry}
Users Updated: ${results.updated}
----------------------------------------`;

    console.log(summary);

    return {
      ...results,
      summary,
      timeStats: {
        totalProcessingTime: totalTime,
        averageTimePerUser,
        timestamp: new Date().toISOString(),
      },
      databaseStats: {
        totalUsers: totalUsersCount,
        usersWithCoordinates,
        usersWithCountry,
      },
    };
  } catch (error) {
    console.error("\n❌ Error updating users with no country:");
    console.error("Error message:", error.message);
    console.error("Stack trace:", error.stack);
    throw error;
  }
};

// Initial call to update all users' countries

module.exports = {
  checkIfAnsweredToday,
  updateUserCountry,
  updateAllUsersCountries,
  updateUsersWithNoCountry, // Export the new function
}; // Export the function using CommonJS
