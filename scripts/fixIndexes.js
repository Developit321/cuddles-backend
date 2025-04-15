/**
 * MongoDB Index Repair Script
 *
 * This script drops all existing geospatial indexes and recreates them properly
 * Run this script with: node scripts/fixIndexes.js
 */

const mongoose = require("mongoose");
const User = require("../models/User");

async function fixIndexes() {
  try {
    console.log("Connecting to MongoDB...");
    await mongoose.connect(
      "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/"
    );
    console.log("Connected to MongoDB");

    const collection = User.collection;

    // List all indexes
    console.log("Getting list of current indexes...");
    const indexes = await collection.listIndexes().toArray();
    console.log(
      "Current indexes:",
      indexes.map((idx) => idx.name)
    );

    // Drop all location-related indexes
    console.log("Dropping all location indexes...");
    const locationIndexes = indexes.filter(
      (idx) =>
        idx.name === "location_2dsphere" ||
        idx.name === "location_coordinates_2dsphere" ||
        idx.name === "location.coordinates_2dsphere"
    );

    for (const idx of locationIndexes) {
      try {
        console.log(`Dropping index: ${idx.name}`);
        await collection.dropIndex(idx.name);
        console.log(`Successfully dropped ${idx.name}`);
      } catch (err) {
        console.error(`Error dropping index ${idx.name}:`, err.message);
      }
    }

    // Create the new index
    console.log("Creating new geospatial index with proper configuration...");
    try {
      await collection.createIndex(
        { "location.coordinates": "2dsphere" },
        {
          name: "location_coordinates_2dsphere",
          background: true,
          sparse: true, // Only index documents where the field exists
        }
      );
      console.log("Successfully created location_coordinates_2dsphere index");
    } catch (err) {
      console.error("Error creating index:", err.message);
    }

    // Verify the new indexes
    console.log("Verifying indexes after update...");
    const updatedIndexes = await collection.listIndexes().toArray();
    console.log(
      "Updated indexes:",
      updatedIndexes.map((idx) => idx.name)
    );

    // Get and print details of our new index
    const newIndex = updatedIndexes.find(
      (idx) => idx.name === "location_coordinates_2dsphere"
    );
    if (newIndex) {
      console.log("New index details:", JSON.stringify(newIndex, null, 2));
    } else {
      console.error("New index does not appear to exist!");
    }

    console.log("Index repair complete!");
  } catch (err) {
    console.error("Error fixing indexes:", err);
  } finally {
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  }
}

// Run the fix
fixIndexes();
