const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./models/User");

// Replace with your MongoDB connection string
const MONGODB_URI = "mongodb://localhost:27017/cuddles"; // Update this with your actual MongoDB URI

async function createAdminUser() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGODB_URI);
    console.log("Connected to MongoDB");

    // Admin user details
    const adminEmail = "admin@cuddles.com";
    const adminPassword = "Admin123!"; // Change this to your desired password
    const adminName = "Admin";

    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log("Admin user already exists with email:", adminEmail);

      // Update the password if it's null
      if (!existingAdmin.password) {
        console.log("Updating admin password...");
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(adminPassword, salt);

        existingAdmin.password = hashedPassword;
        await existingAdmin.save();
        console.log("Admin password updated successfully!");
      }
    } else {
      // Create new admin user
      console.log("Creating new admin user...");

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(adminPassword, salt);

      const adminUser = new User({
        name: adminName,
        email: adminEmail,
        password: hashedPassword,
        age: "25",
        verified: true,
      });

      await adminUser.save();
      console.log("Admin user created successfully!");
    }

    console.log("\nAdmin Login Credentials:");
    console.log("Email:", adminEmail);
    console.log("Password:", adminPassword);
    console.log("\n⚠️  Please change this password after first login!");
  } catch (error) {
    console.error("Error creating admin user:", error);
  } finally {
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  }
}

createAdminUser();
