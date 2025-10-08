const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./models/User");

// MongoDB Atlas connection string from your index.js
const MONGODB_URI =
  "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/";

async function fixUserPassword() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGODB_URI);
    console.log("Connected to MongoDB");

    // Email of the user to fix
    const userEmail = "cuddlesquery@gmail.com";
    const newPassword = "c"; // Change this to your desired password

    // Find the user
    const user = await User.findOne({ email: userEmail });
    if (!user) {
      console.log("User not found with email:", userEmail);
      return;
    }

    console.log("User found:", user.email);
    console.log("Current password value:", user.password);

    // Update the password
    console.log("Setting new password...");
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    await user.save();

    console.log("Password updated successfully!");
    console.log("\nLogin Credentials:");
    console.log("Email:", userEmail);
    console.log("Password:", newPassword);
    console.log("\n⚠️  Please change this password after login!");
  } catch (error) {
    console.error("Error fixing user password:", error);
  } finally {
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  }
}

fixUserPassword();
