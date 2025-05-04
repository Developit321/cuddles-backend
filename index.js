const bodyParser = require("body-parser");
const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");
const User = require("./models/User");
const Report = require("./models/Report");
const SharedQuestion = require("./models/SharedQuestion");
const Question = require("./models/ Question");
const Message = require("./models/message");
const jwt = require("jsonwebtoken");
const cloudinary = require("cloudinary");
const app = express();
const port = 3000;
const multer = require("multer");
const { resolve } = require("path");
const Chat = require("./models/message");
const http = require("http").createServer(app);
const io = require("socket.io")(http); // Pass the HTTP server instance
const bcrypt = require("bcryptjs");
const { sendNotification } = require("./notifications/pushNotifications");

const userRoutes = require("./routes/userRoutes");

// Helper function to calculate distance between two coordinates
function calculateDistance(lat1, lon1, lat2, lon2) {
  if (!lat1 || !lon1 || !lat2 || !lon2) return null;

  const R = 6371; // Earth's radius in kilometers
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distance in kilometers
}

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
// Routes
app.use("/api/users", userRoutes);

// controllers
const { getUnreadCounts } = require("./Controllers/conversationController");
const { profile } = require("console");

// Configure multer for file handling
const storage = multer.memoryStorage(); // Store files in memory
const upload = multer({ storage });

// Cloudinary configuration
cloudinary.config({
  cloud_name: "dfnwpmv4l",
  api_key: "816434434476967",
  api_secret: "xm7lG-Q39W1TyL9HK6lTaLGXmFA",
});

// MongoDB connection
mongoose
  .connect(
    "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/"
  )
  .then(async () => {
    console.log("Connected to the Database");
  })
  .catch((error) => {
    console.log("Error connecting to the Database", error);
  });

http.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

module.exports = mongoose;

// Socket.io connection
io.on("connection", (socket) => {
  // Listen for the join event and make the user join a specific room
  socket.on("join", ({ userId }) => {
    socket.join(userId); // User joins a room with their own userId
    // Emit a success message back to the client
    socket.emit("joinSuccess", {
      status: 200,
      message: "Joined room successfully",
    });
  });

  // Join a user to a specific group chat room
  socket.on("joinGroup", ({ userId, groupId }) => {
    socket.join(groupId);
    socket.emit("joinGroupSuccess", {
      status: 200,
      message: `Joined group ${groupId} successfully`,
    });
  });

  /// send group message
  socket.on("sendGroupMessage", async ({ senderId, groupId, message }) => {
    try {
      const newGroupMessage = new GroupMessage({
        groupId,
        senderId,
        message,
        timestamp: new Date(),
      });

      await newGroupMessage.save();
      io.to(groupId).emit("receiveGroupMessage", newGroupMessage);
      console.log(`Message sent to group ${groupId}:`, message);
    } catch (error) {
      console.error("Error sending group message:", error);
    }
  });

  // Listen for incoming messages
  socket.on("sendMessage", async ({ senderId, receiverId, message }) => {
    try {
      console.log("Message received from client:", {
        senderId,
        receiverId,
        message,
      });

      const recieverInfo = await User.findById(receiverId).select("pushToken");

      const newMessage = new Message({ senderId, receiverId, message });
      const updatedUser = await User.findOneAndUpdate(
        { _id: receiverId, "conversations.receiverId": senderId },
        { $inc: { "conversations.$.unreadMessagesCount": 1 } },
        { new: true }
      );

      // If the conversation was not found, add a new one
      if (!updatedUser) {
        await User.findOneAndUpdate(
          { _id: receiverId },
          {
            $push: {
              conversations: {
                receiverId: senderId,
                unreadMessagesCount: 1,
              },
            },
          }
        );
      }
      await newMessage.save();

      // Emit the message to the receiver's room
      io.to(receiverId).emit("receiveMessage", newMessage); // Emit to the room based on receiverId

      if (recieverInfo.pushToken) {
        await sendNotification(recieverInfo.pushToken, "Message", message);
      }
    } catch (error) {
      console.error("Error saving message:", error);
    }
  });
  // Listen for marking messages as read
  socket.on("markAsRead", async ({ userId, senderId }) => {
    try {
      // Reset the unread messages count to zero
      const updatedUser = await User.findOneAndUpdate(
        { _id: senderId, "conversations.receiverId": userId },
        { $set: { "conversations.$.unreadMessagesCount": 0 } },
        { new: true }
      );

      // Optionally, you can emit an update event to the sender or other relevant clients
      if (updatedUser) {
        // Emit an event to notify about the updated unread count
        io.to(senderId).emit("updateUnreadCount", { senderId, unreadCount: 0 });
      }
    } catch (error) {
      console.error("Error marking messages as read:", error);
    }
  });

  app.get("/group/messages/:groupName", async (req, res) => {
    const { groupName } = req.params;

    try {
      // Validate the groupName
      if (!["Good Times", "Vibes", "Friendships"].includes(groupName)) {
        return res.status(400).json({ message: "Invalid group name" });
      }

      const messages = await GroupMessage.find({ groupName })
        .sort({ createdAt: 1 }) // Sort by createdAt in ascending order
        .select("senderId message createdAt"); // Select only necessary fields

      res.status(200).json(messages);
    } catch (error) {
      console.error("Error fetching group messages:", error);
      res.status(500).json({ message: "Server error" });
    }
  });

  // set read messages to true
  app.post("/messages/read", async (req, res) => {
    const { userId, senderId } = req.body;

    try {
      // Find and update the unread messages for the specified conversation
      const updatedMessages = await Chat.updateMany(
        {
          $or: [
            { senderId: senderId, receiverId: userId, read: false }, // Messages sent by the sender
            { senderId: userId, receiverId: senderId, read: false }, // Messages sent by the receiver
          ],
        },
        { $set: { read: true } },
        { multi: true } // Update multiple documents
      );

      if (updatedMessages.nModified === 0) {
        return res.status(404).json({ message: "No unread messages found" });
      }

      // Update the user's conversation to reset unread count
      const user = await User.findOneAndUpdate(
        { _id: userId, "conversations.receiverId": senderId },
        { $set: { "conversations.$.unreadMessagesCount": 0 } },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({ message: "Conversation not found" });
      }

      return res.status(200).json({ message: "Messages marked as read", user });
    } catch (error) {
      console.error("Error marking messages as read:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  });

  // Handle user disconnect
  socket.on("disconnect", () => {
    // console.log("A user disconnected: " + socket.id);
  });
});

// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, age } = req.body;

    console.log(name, email, age);

    // Validate required fields for all users
    if (!name || !email || !age) {
      return res
        .status(400)
        .json({ message: "Name, email, and age are required" });
    }

    // Ensure email is in a valid format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    // Convert email to lowercase for consistency
    const normalizedEmail = email.toLowerCase();

    // Check if the user already exists
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      // Generate a JWT token for the existing user
      const token = jwt.sign({ userId: existingUser._id }, secretKey);

      // Respond with the token and a message indicating the user already exists
      return res.status(200).json({
        message: "User already exists. Here's your token.",
        token,
        userId: existingUser._id,
      });
    }

    let hashedPassword = null;

    // If a password is provided, validate and hash it
    if (password) {
      if (password.length < 8) {
        return res.status(400).json({
          message: "Password must be at least 8 characters long",
        });
      }
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    // Create a new user
    const newUser = new User({
      name,
      email: normalizedEmail,
      password: hashedPassword, // Will be null if no password is provided
      age,
    });

    // Generate a verification token
    newUser.VerificationToken = crypto.randomBytes(20).toString("hex");

    // Save the new user to the database
    await newUser.save();

    // Generate a JWT token
    const token = jwt.sign({ userId: newUser._id }, secretKey);

    // Respond with success
    res.status(201).json({ token, userId: newUser._id });
  } catch (error) {
    console.error("Error during registration:", error);

    // MongoDB validation errors
    if (error.name === "ValidationError") {
      return res.status(400).json({
        message: "Validation error",
        details: error.errors,
      });
    }

    // Handle duplicate key errors (e.g., email already exists)
    if (error.code === 11000) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Generic error handling
    res.status(500).json({
      message: "An unexpected error occurred during registration",
      error: error.message,
    });
  }
});

// Change Password API
app.post("/change-password/:userId", async (req, res) => {
  "";
  try {
    const { userId } = req.params;
    const { currentPassword, newPassword } = req.body;

    // Check if both current and new password are provided
    if (!currentPassword || !newPassword) {
      return res
        .status(400)
        .json({ message: "Please provide both current and new password." });
    }

    // Find the user by their ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Compare the current password with the user's hashed password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect current password." });
    }

    // Hash the new password
    const saltRounds = 10;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password in the database
    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "cuddlesquery@gmail.com",
    pass: "nlvj jxji vkni ftxv",
  },
});
// Send verification email
const sendVerificationEmail = async (email, VerificationToken) => {
  const mailOptions = {
    from: "cuddles.com",
    to: email,
    subject: "Email verification",
    text: `Click on this link to verify your email: https://cuddles-batcat.onrender.com/verify/${VerificationToken}`,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log("Error sending the verification email", error);
  }
};

// Verify user
app.get("/verify/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ VerificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid verification code" });
    }

    // Mark the user as verified
    user.verified = true;
    user.VerificationToken = undefined;

    await user.save();

    res.status(200).json({ message: "Email verified" });
  } catch (error) {
    console.log("Email verification failed", error);
    res.status(500).json({ message: "Email verification failed" });
  }
});

const generateSecreteKey = () => {
  const secretKey = crypto.randomBytes(32).toString("hex");
  return secretKey;
};

const secretKey = generateSecreteKey();

//login user

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(email);
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      console.log("no user ");
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, secretKey);

    // Send back both the token and user ID
    res.status(200).json({ token, userId: user._id });
  } catch (error) {
    console.log("Error logging in the user", error);
    res.status(500).json({ message: "Login failed" });
  }
});
//gender change endpoint

app.put("/users/:userId/gender", async (req, res) => {
  try {
    const { userId } = req.params;
    const { gender } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { gender: gender },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res.status(200).json({ message: "user gender updated Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating user gender", error });
  }
});

// gender preferences

app.put("/users/:userId/preferences", async (req, res) => {
  try {
    const { userId } = req.params;
    const { preferences } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { preferences: preferences },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res.status(200).json({ message: "user gender updated Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating user gender", error });
  }
});
//description endpoint

app.put("/users/:userId/description", async (req, res) => {
  try {
    const { userId } = req.params;
    const { description } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { description: description },
      { new: true }
    );
    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res
      .status(200)
      .json({ message: "user description updated Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "error updating the users description" });
  }
});

// set interest endpoint

app.put("/users/:userId/interests/add", async (req, res) => {
  try {
    const { userId } = req.params;
    const { interests } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { interests: interests } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res
      .status(200)
      .json({ message: "user interestts added Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "error updating the users interests" });
  }
});

//remove interests

app.delete("/users/:userId/interests/remove", async (req, res) => {
  try {
    const { userId } = req.params;
    const { interest } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { interests: interest } }, // Remove a single interest
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res
      .status(200)
      .json({ message: "User interest removed successfully" });
  } catch (error) {
    res.status(500).json({
      message: "Error removing the user's interest",
      error: error.message,
    });
  }
});

//looking for endpoint

app.put("/users/:userId/lookingfor/add", async (req, res) => {
  try {
    const { userId } = req.params;
    const { lookingFor } = req.body;

    const validOptions = ["Friendship", "Goodtime", "Long term relationship"];

    if (
      !Array.isArray(lookingFor) ||
      lookingFor.some((item) => !validOptions.includes(item))
    ) {
      return res.status(400).json({
        message:
          "Invalid lookingFor data. Please choose from 'friendship', 'goodtime', or 'long term relationship'.",
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { lookingFor: { $each: lookingFor } } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res
      .status(200)
      .json({ message: "User's 'looking for' updated successfully", user });
  } catch (error) {
    console.error("Error updating 'looking for':", error);
    return res
      .status(500)
      .json({ message: "Error updating the user's 'looking for'" });
  }
});

app.put("/users/:userId/availability/add", async (req, res) => {
  try {
    const { userId } = req.params;
    const { availability } = req.body;

    const validOptions = ["morning", "afternoon", "evening"];

    if (
      !Array.isArray(availability) ||
      availability.some((item) => !validOptions.includes(item))
    ) {
      return res.status(400).json({
        message:
          "Invalid availability data. Please choose from 'morning', 'afternoon', or 'evening'.",
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { availability: { $each: availability } } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res
      .status(200)
      .json({ message: "User's 'looking for' updated successfully", user });
  } catch (error) {
    console.error("Error updating 'looking for':", error);
    return res
      .status(500)
      .json({ message: "Error updating the user's 'availability'" });
  }
});

app.put("/users/:userId/cuddle-preference", async (req, res) => {
  try {
    const { userId } = req.params;
    let { expectations } = req.body;

    if (!Array.isArray(expectations) || expectations.length === 0) {
      return res
        .status(400)
        .json({ message: "Preferences should be a non-empty array." });
    }

    // Sanitize input: Remove empty values & trim whitespace
    expectations = expectations
      .map((item) => (typeof item === "string" ? item.trim() : null))
      .filter((item) => item);

    if (expectations.length === 0) {
      return res
        .status(400)
        .json({ message: "Preferences cannot be empty after sanitization." });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { expectations },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "Cuddle preferences updated successfully",
      expectations: user.expectations, // Return updated preferences
    });
  } catch (error) {
    console.error("Error updating cuddle expectations:", error);
    return res.status(500).json({
      message: "Error updating the user's cuddle expectations",
      error: error.message,
    });
  }
});

// DELETE route to remove an item from the lookingFor array
app.delete("/users/:userId/lookingfor/remove", async (req, res) => {
  try {
    const { userId } = req.params;
    const { lookingForItem } = req.body;

    // Validate the lookingForItem is a string
    if (typeof lookingForItem !== "string") {
      return res
        .status(400)
        .json({ message: "Invalid 'lookingForItem'. Must be a string." });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { lookingFor: lookingForItem } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "User 'looking for' item removed successfully",
      updatedLookingFor: user.lookingFor,
    });
  } catch (error) {
    console.error("Error removing 'looking for' item:", error);
    return res.status(500).json({
      message: "Error removing the user's 'looking for' item",
      error: error.message,
    });
  }
});

app.get("/users/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const userData = await User.findById(userId);

    if (!userData) {
      return res.status(404).json({ message: "user data not found" });
    }
    return res.status(200).json(userData);
  } catch (error) {
    res.status(500).json({ message: "error fetching the users data" });
  }
});

//image upload

app.post("/users/:userId/upload", upload.single("file"), async (req, res) => {
  const userId = req.params.userId;

  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    // Step 1: Detect faces in the uploaded image

    // Step 2: Upload the image to Cloudinary
    let imageUrl;
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        (uploadResult, error) => {
          if (error) {
            console.log("Cloudinary upload error:", error);
            return reject(error);
          }

          imageUrl = uploadResult.secure_url;
          resolve(uploadResult); // Resolve the promise with the upload result
        }
      );
      uploadStream.end(req.file.buffer);
    });

    // Step 3: Update the user's profile with the uploaded image URL
    if (imageUrl) {
      console.log(userId, imageUrl);
      const user = await User.findByIdAndUpdate(
        userId,
        { $addToSet: { profileImages: imageUrl } },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
    }

    return res.status(200).json({ message: "Upload was a success", imageUrl });
  } catch (error) {
    console.error("File upload failed:", error);
    res.status(500).json({ error: "File upload failed" });
  }
});
// endpoint to fetch users

app.get("/profiles", async (req, res) => {
  try {
    const {
      userId,
      gender,
      lookingFor,
      minAge = "21",
      maxAge = "100",
      longitude,
      latitude,
    } = req.query;

    // Input validation
    if (!mongoose.Types.ObjectId.isValid(userId) || !gender) {
      return res
        .status(400)
        .json({ message: "Invalid userId or missing gender" });
    }

    // Fetch only needed fields from current user
    const currentUser = await User.findById(userId)
      .select("gender Matches crushes profileDislikes")
      .lean();

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Convert all ObjectIds to strings for consistent handling
    const userIdStr = userId.toString();
    const matchIds = (currentUser.Matches || []).map((id) => id.toString());
    const crushIds = (currentUser.crushes || []).map((id) => id.toString());
    const dislikeIds = (currentUser.profileDislikes || []).map((id) =>
      id.toString()
    );

    // All IDs to exclude
    const excludedIds = [userIdStr, ...matchIds, ...crushIds, ...dislikeIds];

    // Convert back to ObjectIds for MongoDB
    const excludedObjectIds = excludedIds.map((id) =>
      mongoose.Types.ObjectId.isValid(id) ? new mongoose.Types.ObjectId(id) : id
    );

    // Base query criteria - this properly excludes all profiles we don't want to see
    const baseMatch = {
      _id: { $nin: excludedObjectIds },
      gender:
        gender === "both"
          ? currentUser.gender === "male"
            ? "female"
            : "male"
          : gender,
      age: {
        $gte: minAge.toString(),
        $lte: maxAge.toString(),
      },
      profileImages: { $exists: true, $not: { $size: 0 } },
      $or: [
        { anonymous: { $exists: false } }, // Include profiles where anonymous field doesn't exist yet
        { anonymous: false }, // Or where anonymous is explicitly false
      ],
      $and: [
        {
          $or: [
            { flagged: { $exists: false } }, // Include profiles where flagged field doesn't exist yet
            { flagged: { $ne: true } }, // Or where flagged is not true
          ],
        },
      ],
    };

    // Add lookingFor filter if provided
    if (lookingFor) {
      baseMatch.lookingFor = {
        $in: Array.isArray(lookingFor) ? lookingFor : [lookingFor],
      };
    }

    // Sequential approach to fetch profiles
    let profiles = [];
    let hasLocation = false;

    // Step 1: First try to get nearby profiles if location is provided
    if (longitude && latitude) {
      try {
        const parsedLong = parseFloat(longitude);
        const parsedLat = parseFloat(latitude);

        if (!isNaN(parsedLong) && !isNaN(parsedLat)) {
          hasLocation = true;

          // Fetch nearby profiles using geospatial query
          const nearbyProfiles = await User.aggregate([
            {
              $geoNear: {
                near: {
                  type: "Point",
                  coordinates: [parsedLong, parsedLat],
                },
                distanceField: "distance",
                maxDistance: 50000, // 50km radius
                spherical: true,
                query: baseMatch,
                distanceMultiplier: 0.001, // Convert to kilometers
                key: "location",
              },
            },
            { $limit: 20 }, // Limit to 20 nearby profiles
          ]).option({
            maxTimeMS: 5000,
          });

          console.log(`Found ${nearbyProfiles.length} nearby profiles`);
          profiles = nearbyProfiles;
        }
      } catch (error) {
        console.error("Error in geospatial query:", error);
        // Continue to other profile types if geospatial query fails
      }
    }

    // Step 2: If we don't have enough profiles, get priority profiles
    if (profiles.length < 20) {
      // Get IDs of profiles we already have to avoid duplicates
      const existingProfileIds = new Set(profiles.map((p) => p._id.toString()));
      const neededProfiles = 20 - profiles.length;

      // Find priority users that match our criteria and aren't already in results
      const priorityProfiles = await User.find({
        _id: { $nin: [...excludedObjectIds, ...existingProfileIds] },
        priority: 1,
        ...baseMatch,
      })
        .limit(neededProfiles)
        .lean();

      console.log(`Found ${priorityProfiles.length} priority profiles`);

      // Add priority profiles to our results
      for (const profile of priorityProfiles) {
        profiles.push(profile);
        existingProfileIds.add(profile._id.toString());
      }

      // Step 3: If we still don't have enough profiles, get newest users
      if (profiles.length < 20) {
        const neededAfterPriority = 20 - profiles.length;

        // Find newest users that match our criteria and aren't already in results
        const newestProfiles = await User.find({
          _id: { $nin: [...excludedObjectIds, ...existingProfileIds] },
          ...baseMatch,
        })
          .sort({ createdAt: -1 })
          .limit(neededAfterPriority)
          .lean();

        console.log(`Found ${newestProfiles.length} newest profiles`);

        // Add newest profiles to our results
        profiles.push(...newestProfiles);
      }
    }

    console.log(`Total profiles found: ${profiles.length}`);

    // Apply in-memory shuffle for randomness
    const shuffledProfiles = profiles.sort(() => Math.random() - 0.5);

    // Calculate distances for profiles missing distance field
    if (hasLocation && shuffledProfiles.length > 0) {
      const parsedLong = parseFloat(longitude);
      const parsedLat = parseFloat(latitude);

      shuffledProfiles.forEach((profile) => {
        if (
          !profile.distance &&
          profile.location &&
          profile.location.coordinates
        ) {
          profile.distance = calculateDistance(
            parsedLat,
            parsedLong,
            profile.location.coordinates[1],
            profile.location.coordinates[0]
          );
        }
      });
    }

    // Log gender counts
    const genderCounts = shuffledProfiles.reduce((counts, profile) => {
      counts[profile.gender] = (counts[profile.gender] || 0) + 1;
      return counts;
    }, {});

    return res.status(200).json({
      profiles: shuffledProfiles,
      totalCount: shuffledProfiles.length,
      nearbyCount: shuffledProfiles.filter((p) => p.distance != null).length,
    });
  } catch (error) {
    console.error("Error fetching user profiles:", error);
    res.status(500).json({ message: "Error fetching user profiles" });
  }
});

app.post("/likeprofile", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId).select(
      "pushToken recievedLikes"
    );

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user has already liked the selected user
    const alreadyLiked = selectedUser.recievedLikes.includes(currentUserId);
    const alreadyCrush = currentUser.crushes.includes(selectedUserId);

    if (alreadyLiked || alreadyCrush) {
      console.log("You already liked this user.");
      return res
        .status(400)
        .json({ message: "You have already liked this user." });
    }

    // Update the recipient's likes if not already liked
    await User.findByIdAndUpdate(selectedUserId, {
      $push: { recievedLikes: currentUserId },
    });

    // Update the current user's crushes if not already added
    await User.findByIdAndUpdate(currentUserId, {
      $push: { crushes: selectedUserId },
    });

    // Send notification to the selected user if they have a push token
    if (selectedUser.pushToken) {
      const title = "Someone likes your profile!";
      const body = `${currentUser.name || "A user"} has liked your profile.`;
      await sendNotification(selectedUser.pushToken, title, body);
    }

    return res.status(200).json({ message: "Profile liked successfully." });
  } catch (error) {
    console.error("Error liking profile:", error); // Log the actual error to the server console
    return res
      .status(500)
      .json({ message: "Failed to like profile", error: error.message });
  }
});

// get the people that liked your profile

app.get("/recievedLikes/:userId/info", async (req, res) => {
  try {
    const { userId } = req.params;

    // Retrieve the current user along with their crushes
    const currentUser = await User.findById(userId).populate("crushes", "_id");

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Extract the IDs of the current user's crushes
    const deslikedProfileId = (currentUser.profileDislikes || []).map(
      (profileDeslike) => profileDeslike._id
    );

    // Find users in the recievedLikes array but exclude users that are in crushes
    const recievedLikesArray = await User.find({
      _id: { $in: currentUser.recievedLikes, $nin: deslikedProfileId }, // Filter out crushes
    });

    // Return the filtered received likes
    return res.status(200).json(recievedLikesArray);
  } catch (error) {
    console.error("Error fetching received likes:", error);
    res.status(500).json({ message: "Failed to retrieve the received likes" });
  }
});

app.post("/create-match", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    //update the selected users recieved  likes and matches
    await User.findByIdAndUpdate(selectedUserId, {
      $push: { Matches: currentUserId },
      $pull: { recievedLikes: currentUserId },
    });

    //update the current users  reived likes and matches
    await User.findByIdAndUpdate(currentUserId, {
      $push: { Matches: selectedUserId },
      $pull: { recievedLikes: selectedUserId },
    });

    // Fetch the selected user's expo push token
    const selectedUser = await User.findById(selectedUserId).select(
      "pushToken"
    );

    // Only send notification if the expoPushToken is available
    if (selectedUser && selectedUser.pushToken) {
      const title = "You have a new match!";
      const body = "You and someone else have matched! Check it out.";
      await sendNotification(selectedUser.pushToken, title, body);
    }
    res.sendStatus(200);
    console.log("new match ");
  } catch (error) {
    res.status(500).json({ message: "failed to match the users", error });
  }
});

// fetch the users you matched with

app.get("/matches/:userId/info", async (req, res) => {
  try {
    const { userId } = req.params;

    // Find the user by userId
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Get the user's match IDs
    const matchIds = user.Matches;

    // Fetch matches based on match IDs
    const matches = await User.find({ _id: { $in: matchIds } });

    // Filter out matches that have the current user in their blockedBy array
    const filteredMatches = matches.filter(
      (match) => !match.blockedBy.includes(userId)
    );

    // Populate each match with the latest message details and unread count
    const updatedMatches = await Promise.all(
      filteredMatches.map(async (match) => {
        const latestMessage = await fetchLatestMessage(userId, match._id);

        // Find the conversation for the current match
        const conversation = user.conversations.find(
          (conv) => conv.receiverId.toString() === match._id.toString()
        );

        return {
          ...match.toObject(),
          lastMessage: latestMessage?.message || "No messages",
          timestamp: latestMessage?.timestamp || null,
          typing: latestMessage?.typing || false,
          unreadCount: conversation ? conversation.unreadMessagesCount : 0, // Get unread count from conversations
        };
      })
    );

    // Sort matches by the timestamp of the latest message
    const sortedMatches = updatedMatches.sort((a, b) => {
      const aTime = a.timestamp ? new Date(a.timestamp) : 0; // Convert to date object
      const bTime = b.timestamp ? new Date(b.timestamp) : 0; // Convert to date object
      return bTime - aTime; // Sort in descending order
    });

    // Return the filtered and updated matches with latest messages
    res.status(200).json(sortedMatches);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to retrieve matches and latest messages." });
  }
});

// Helper function to fetch the latest message between two users
const fetchLatestMessage = async (userId, matchId) => {
  // Find the latest message between the users
  const latestMessage = await Message.findOne({
    $or: [
      { senderId: userId, receiverId: matchId },
      { senderId: matchId, receiverId: userId },
    ],
  })
    .sort({ timestamp: -1 }) // Sort by timestamp, assuming it's the field you're using
    .lean();

  return latestMessage || {};
};

// Delete inappropriate image from user profile
app.delete("/users/:userId/images", async (req, res) => {
  try {
    const { userId } = req.params;
    const { imageUrl, reason } = req.body;

    // Validate input
    if (!userId || !imageUrl) {
      return res.status(400).json({ message: "Missing required parameters" });
    }

    // Find the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if the image exists in the user's profile images
    if (!user.profileImages.includes(imageUrl)) {
      return res
        .status(404)
        .json({ message: "Image not found in user profile" });
    }

    // Remove the image from the profileImages array
    user.profileImages = user.profileImages.filter((img) => img !== imageUrl);
    await user.save();

    // Log the moderation action
    console.log(
      `Image deleted from user ${userId} for reason: ${
        reason || "No reason provided"
      }`
    );

    return res.status(200).json({
      message: "Image deleted successfully",
      remainingImages: user.profileImages.length,
    });
  } catch (error) {
    console.error("Error deleting image:", error);
    return res.status(500).json({ message: "Failed to delete image" });
  }
});

app.get("/messages/:senderId/:receiverId", async (req, res) => {
  const { senderId, receiverId } = req.params;
  const { skip = 0, limit = 20 } = req.query;
  try {
    // Fetch messages based on senderId and receiverId with pagination
    const messages = await Message.find({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId },
      ],
    })
      .sort({ timestamp: -1 }) // Sort messages by timestamp in descending order
      .skip(Number(skip)) // Skip the first `skip` messages
      .limit(Number(limit)); // Limit to `limit` messages

    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: "Error fetching messages" });
  }
});

// API endpoint to save multiple messages
app.post("/messages/save", async (req, res) => {
  try {
    const messages = req.body;

    // Create an array of Chat message instances
    const chatMessages = messages.map((msg) => ({
      senderId: msg.senderId,
      receiverId: msg.receiverId,
      message: msg.message,
      timestamp: new Date(msg.timestamp),
    }));

    // Save all messages to the database
    const savedMessages = await Chat.insertMany(chatMessages);

    res.status(201).json({
      success: true,
      message: "Messages saved successfully",
      data: savedMessages,
    });
  } catch (error) {
    console.error("Error saving messages:", error);
    res.status(500).json({
      success: false,
      message: "Error saving messages",
      error: error.message,
    });
  }
});

app.put("/push-notification-token/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { pushToken } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { pushToken: pushToken },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res
      .status(200)
      .json({ message: "user pushToken updated successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error updating users push token ", error });
  }
});

// add users location

app.post("/user/:userId/update-location", async (req, res) => {
  try {
    const { userId } = req.params;
    const { longitude, latitude } = req.body;

    // Parse and validate coordinates
    const parsedLong = parseFloat(longitude);
    const parsedLat = parseFloat(latitude);

    if (isNaN(parsedLong) || isNaN(parsedLat)) {
      return res.status(400).json({ error: "Invalid coordinates format" });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          location: {
            type: "Point",
            coordinates: [parsedLong, parsedLat],
          },
        },
      },
      { new: true } // Return the updated user document
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Log success and respond
    console.log("User coordinates updated successfully");
    return res
      .status(200)
      .json({ message: "Location updated successfully", user });
  } catch (error) {
    console.error("Error updating user's location:", error); // Log any errors
    return res
      .status(500)
      .json({ message: "Error updating user's location", error });
  }
});

// fetch users that are close to each other due to location

app.get("/nearby-users", async (req, res) => {
  const MAX_DISTANCE_METERS = 50000;
  try {
    const { longitude, latitude, maxDistance } = req.query;
    if (!longitude || !latitude || !maxDistance) {
      return res
        .status(400)
        .json({ error: "Longitude, latitude, and maxDistance are required" });
    }

    // Parse coordinates
    const parsedLong = parseFloat(longitude);
    const parsedLat = parseFloat(latitude);

    // Validate parsed coordinates
    if (isNaN(parsedLong) || isNaN(parsedLat)) {
      return res.status(400).json({ error: "Invalid coordinates format" });
    }

    const nearbyUsers = await User.aggregate([
      {
        $geoNear: {
          near: {
            type: "Point",
            coordinates: [parsedLong, parsedLat],
          },
          distanceField: "distance",
          maxDistance: MAX_DISTANCE_METERS,
          spherical: true,
          query: {
            profileImages: { $exists: true, $not: { $size: 0 } },
          },
          distanceMultiplier: 0.001, // Convert to kilometers
        },
      },
      {
        $project: {
          _id: 1,
          name: 1,
          location: 1,
          profileImages: 1,
          pushToken: 1,
          distance: 1,
        },
      },
    ]);

    if (nearbyUsers.length === 0) {
      return res.status(404).json({ message: "No users found nearby" });
    }
    res.json({ message: "Nearby users found", users: nearbyUsers });
  } catch (error) {
    console.error("Error finding nearby users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Your delete endpoint

app.delete("/users/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    // Validate the userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format." });
    }

    // Convert userId to ObjectId
    const objectId = new mongoose.Types.ObjectId(userId);

    // Find the user by ID and delete
    const deletedUser = await User.findByIdAndDelete(objectId);

    if (!deletedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    return res
      .status(500)
      .json({ message: "Error deleting user", error: error.message });
  }
});

// Endpoint to update profile image
app.put(
  "/update-profile-image/:userId",
  upload.single("file"),
  async (req, res) => {
    const { userId } = req.params;

    try {
      // Check if file is uploaded
      if (!req.file) {
        console.log("image file not uploaded");
        return res.status(400).json({ message: "No image file uploaded" });
      }

      // Upload image to Cloudinary
      let imageUrl;
      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          (uploadResult, error) => {
            if (error) {
              console.log("some errors", error);
              return reject(error);
            }

            imageUrl = uploadResult.secure_url;
            resolve(uploadResult); // Resolve the promise with the upload result
          }
        );
        uploadStream.end(req.file.buffer);
      });

      console.log(userId, imageUrl);

      // Update user profile image in the database
      const updatedUser = await User.findOneAndUpdate(
        { _id: userId },
        { $set: { "profileImages.0": imageUrl } }, // Replace the first image
        { new: true }
      );

      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }

      res.status(200).json({
        message: "Profile image updated successfully",
        profileImages: updatedUser.profileImages,
      });
    } catch (error) {
      console.error("Error updating profile image:", error);
      res.status(500).json({ message: "Server error", error });
    }
  }
);

app.put("/change-username/:userId", async (req, res) => {
  const { userId } = req.params;
  const { newUsername } = req.body;
  try {
    // Find the user by ID and update the username
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update the username
    user.name = newUsername;
    await user.save();

    return res.status(200).json({ message: "Username changed successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/cuddles/request-otp", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
    const otpExpires = Date.now() + 60000; // expires in 1 minute

    // Save OTP and expiration in the user's document
    user.otp = { code: otp, expires: otpExpires };
    await user.save();

    // Send OTP to email
    try {
      const emailResult = await transporter.sendMail({
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP code is ${otp}. It is valid for 1 minute.`,
      });

      console.log("Email sent successfully:", emailResult.messageId);
      res.status(200).json({
        message: "OTP sent to your email.",
        emailSent: true,
        messageId: emailResult.messageId,
      });
    } catch (emailError) {
      console.error("Failed to send email:", emailError);
      // Still save the OTP but notify about email delivery failure
      res.status(200).json({
        message: "OTP generated but email delivery failed. Please try again.",
        emailSent: false,
        error: emailError.message,
      });
    }
  } catch (error) {
    console.error("Error in requesting OTP:", error);
    res.status(500).json({ message: "An error occurred." });
  }
});

app.post("/cuddles/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Verify OTP
    if (!user.otp || user.otp.code !== otp) {
      return res.status(400).json({ message: "Invalid OTP." });
    }

    if (Date.now() > user.otp.expires) {
      return res.status(400).json({ message: "OTP has expired." });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the OTP
    user.password = hashedPassword;
    user.otp = undefined; // Clear OTP
    await user.save();

    res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    console.error("Error in changing password:", error);
    res.status(500).json({ message: "An error occurred." });
  }
});

app.post("/addToCrushes", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and the selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId);

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user already has the selected user in their crushes
    const alreadyCrush = currentUser.crushes.some((crush) =>
      crush.equals(selectedUser._id)
    );

    if (alreadyCrush) {
      return res
        .status(400)
        .json({ message: "You have already added this user to your crushes." });
    }

    // Add the selected user's ObjectId to the current user's crushes
    await User.findByIdAndUpdate(currentUserId, {
      $push: { crushes: selectedUser._id }, // Adding the ObjectId of the selected user
    });

    return res
      .status(200)
      .json({ message: "User added to crushes successfully." });
  } catch (error) {
    console.error("Error adding user to crushes:", error); // Log the error for debugging
    return res
      .status(500)
      .json({ message: "Failed to add user to crushes", error: error.message });
  }
});

app.post("/addToDislikes", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and the selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId);

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user already has the selected user in their dislikes
    const alreadyDisliked = currentUser.profileDislikes.some(
      (profileDislikes) => profileDislikes.equals(selectedUser._id)
    );

    if (alreadyDisliked) {
      return res.status(400).json({
        message: "You have already added this user to your dislikes.",
      });
    }

    // Add the selected user's ObjectId to the current user's dislikes
    await User.findByIdAndUpdate(currentUserId, {
      $push: { profileDislikes: selectedUser._id },
    });

    return res
      .status(200)
      .json({ message: "User added to dislikes successfully." });
  } catch (error) {
    console.error("Error adding user to dislikes:", error);
    return res.status(500).json({
      message: "Failed to add user to dislikes",
      error: error.message,
    });
  }
});

app.post("/blockUser", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;
    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and the selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId);

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user already has the selected user in their dislikes
    const alreadyBlocked = selectedUser.blockedBy.some((blockedBy) =>
      blockedBy.equals(currentUser)
    );

    // Add the selected user's ObjectId to the current user's dislikes
    await User.findByIdAndUpdate(selectedUser, {
      $push: { blockedBy: currentUser._id },
    });

    return res
      .status(200)
      .json({ message: "User added to blocked successfully." });
  } catch (error) {}
});

app.post("/report", async (req, res) => {
  const { reporterId, reportedUserId, message } = req.body;

  if (!reporterId || !reportedUserId || !message) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    // Check if users exist
    const reporter = await User.findById(reporterId);
    const reportedUser = await User.findById(reportedUserId);
    if (!reporter || !reportedUser) {
      return res.status(404).json({ error: "User not found." });
    }

    // Save report to database
    const report = new Report({ reporterId, reportedUserId, message });
    await report.save();

    // Send report email
    await transporter.sendMail({
      from: "cuddlesquery@gmail.com",
      to: "cuddlesquery@gmail.com",
      subject: "New User Report",
      text: `User with ID ${reporterId} reported user with ID ${reportedUserId}.\n\nMessage: ${message}`,
    });

    res.status(201).json({ message: "Report submitted successfully." });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ error: "An error occurred while submitting the report." });
  }
});

// Get all reports with pagination and status filter
app.get("/report", async (req, res) => {
  try {
    const { page = 1, limit = 10, status = "all" } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build query based on status
    const query = status === "all" ? {} : { status };

    // Get reports with pagination
    const reports = await Report.find(query)
      .populate("reporterId", "name email")
      .populate("reportedUserId", "name email")
      .sort({ date: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const total = await Report.countDocuments(query);

    res.status(200).json({
      reports,
      total,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching reports." });
  }
});

// Get a specific report by ID
app.get("/report/:id", async (req, res) => {
  try {
    const report = await Report.findById(req.params.id)
      .populate("reporterId", "name email")
      .populate("reportedUserId", "name email");

    if (!report) {
      return res.status(404).json({ error: "Report not found." });
    }

    res.status(200).json(report);
  } catch (error) {
    console.error("Error fetching report:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching the report." });
  }
});

// Resolve a report
app.put("/report/:id/resolve", async (req, res) => {
  try {
    const { action, notes } = req.body;
    const reportId = req.params.id;

    if (!action) {
      return res.status(400).json({ error: "Action is required." });
    }

    const report = await Report.findById(reportId);
    if (!report) {
      return res.status(404).json({ error: "Report not found." });
    }

    // Update report status
    report.status = "resolved";
    report.action = action;
    report.notes = notes;
    report.resolvedAt = new Date();
    await report.save();

    // If action is 'block', update the reported user's status
    if (action === "block") {
      await User.findByIdAndUpdate(report.reportedUserId, {
        $set: { status: "blocked" },
      });
    }

    res.status(200).json({ message: "Report resolved successfully.", report });
  } catch (error) {
    console.error("Error resolving report:", error);
    res
      .status(500)
      .json({ error: "An error occurred while resolving the report." });
  }
});

app.get("/unread-counts/:userId", getUnreadCounts);

app.get("/api/question", async (req, res) => {
  try {
    // Get today's date at midnight
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Start of the day

    // Check if a question has already been shared today
    let sharedQuestion = await SharedQuestion.findOne({
      date: { $gte: today },
    });

    if (sharedQuestion) {
      // If a question has already been shared today, fetch it
      const question = await Question.findById(sharedQuestion.questionId);
      if (question) {
        return res.json({
          message: "Here is your question for today!",
          question: question.question,
          options: question.options,
        });
      }
    }

    // If no question shared today, delete outdated shared questions
    await SharedQuestion.deleteMany({ date: { $lt: today } });

    // Fetch a random question
    const question = await Question.aggregate([{ $sample: { size: 1 } }]);

    if (!question.length) {
      return res.status(404).json({ message: "No questions available." });
    }

    // Save the new question and set the date to today
    const newSharedQuestion = new SharedQuestion({
      date: today, // Use today's date
      questionId: question[0]._id,
    });
    await newSharedQuestion.save();

    // Respond with the random question
    res.json({
      message: "Here is your question for today!",
      question: question[0].question,
      options: question[0].options,
    });
  } catch (error) {
    console.error("Error fetching question:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.post("/:userId/update-daily-question", async (req, res) => {
  try {
    const { question, answer } = req.body;
    const { userId } = req.params;

    console.log(userId, question, answer);

    if (!question || !answer) {
      console.log("Question and answer are required.");
      return res
        .status(400)
        .json({ message: "Question and answer are required." });
    }

    // Find the user by ID
    const user = await User.findById(userId);

    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: "User not found." });
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0); // Reset to the start of today

    // Check if the user's daily question is from today
    if (user.dailyQuestion?.answeredAt) {
      const answeredDate = new Date(user.dailyQuestion.answeredAt);
      answeredDate.setHours(0, 0, 0, 0); // Reset answeredAt to the start of that day

      // If the question is from today, do not allow a new update
      if (answeredDate.getTime() === today.getTime()) {
        return res
          .status(400)
          .json({ message: "Question has already been answered today." });
      }

      // If the question is from a previous day, delete it
      user.dailyQuestion = null;
    }

    // Update the user's daily question with the new one
    user.dailyQuestion = {
      question,
      answer,
      answeredAt: new Date(),
    };

    await user.save();

    res.status(200).json({ message: "Daily question updated successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

app.use("/notify", userRoutes);

const fetchUsersWithPriorityAndLikes = async () => {
  try {
    const users = await User.aggregate([
      {
        $match: {
          priority: 1,
        },
      },
      {
        $addFields: {
          totalLikesAndDislikes: {
            $add: [{ $size: "$profileDislikes" }, { $size: "$recievedLikes" }],
          },
        },
      },
      {
        $match: {
          totalLikesAndDislikes: { $lt: 15 },
        },
      },
      {
        $project: {
          _id: 1, // Only include the user ID in the result
        },
      },
    ]);

    console.log(users);
    return users;
  } catch (error) {
    console.error("Error fetching users:", error);
  }
};

app.put("/user/:userId/name", async (req, res) => {
  try {
    const { userId } = req.params;
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Name is required." });
    }

    // Update the user's name
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { name },
      { new: true } // Return the updated document
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({
      message: "Name updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error updating name:", error);
    res.status(500).json({
      message: "An unexpected error occurred while updating the name.",
      error: error.message,
    });
  }
});

app.put("/user/:userId/age", async (req, res) => {
  try {
    const { userId } = req.params;
    const { age } = req.body;

    if (!age || typeof age !== "number") {
      return res.status(400).json({ message: "Valid age is required." });
    }

    // Update the user's age
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { age },
      { new: true } // Return the updated document
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({
      message: "Age updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error updating age:", error);
    res.status(500).json({
      message: "An unexpected error occurred while updating the age.",
      error: error.message,
    });
  }
});

// Fetch users created between specific dates
app.get("/by-date-range", async (req, res) => {
  try {
    const { startDate, endDate, page = 1, limit = 10 } = req.query;

    console.log(
      `Fetching users between ${startDate} and ${endDate}, page ${page}, limit ${limit}`
    );

    if (!startDate || !endDate) {
      return res
        .status(400)
        .json({ message: "Both start and end dates are required" });
    }

    // Parse dates and create query range
    const start = new Date(startDate);
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999); // Set to end of day

    // Validate dates
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({ message: "Invalid date format" });
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Query users within date range
    const users = await User.find({
      createdAt: { $gte: start, $lte: end },
    })
      .select("name email age gender profileImages createdAt")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalUsers = await User.countDocuments({
      createdAt: { $gte: start, $lte: end },
    });

    console.log(`Found ${totalUsers} users within date range`);

    return res.status(200).json({
      users,
      totalUsers,
      totalPages: Math.ceil(totalUsers / parseInt(limit)),
      currentPage: parseInt(page),
    });
  } catch (error) {
    console.error("Error fetching users by date range:", error);
    res.status(500).json({
      message: "An error occurred while fetching users",
      error: error.message,
    });
  }
});

// Endpoint for sending customizable push notifications from CMS
app.post("/admin/send-notification", async (req, res) => {
  try {
    const { title, body, userIds, allUsers, ignoreWeeklyLimit } = req.body;

    if (!title || !body) {
      return res.status(400).json({ message: "Title and body are required" });
    }

    // Calculate one week ago to check for recent notifications
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    // Build the query for users with push tokens
    let query = { pushToken: { $exists: true, $ne: null } };

    // Add user ID filter if not sending to all users
    if (!allUsers && userIds && userIds.length > 0) {
      query._id = { $in: userIds };
    }

    // Add weekly notification check unless explicitly ignored
    if (!ignoreWeeklyLimit) {
      query.$or = [
        { lastNotificationSent: { $exists: false } },
        { lastNotificationSent: { $lt: oneWeekAgo } },
      ];
    }

    // Find eligible users with push tokens
    const users = await User.find(query);

    // If specific users were requested, calculate how many were filtered out due to recent notifications
    let recentlyNotifiedCount = 0;
    if (!allUsers && userIds && userIds.length > 0 && !ignoreWeeklyLimit) {
      const totalUsersWithTokens = await User.countDocuments({
        _id: { $in: userIds },
        pushToken: { $exists: true, $ne: null },
      });
      recentlyNotifiedCount = totalUsersWithTokens - users.length;
    }

    if (users.length === 0) {
      const message =
        recentlyNotifiedCount > 0
          ? `All selected users (${recentlyNotifiedCount}) were already notified within the last week`
          : "No users found with push tokens";

      return res.status(404).json({ message });
    }

    // Send notifications to all found users
    const notificationPromises = users.map(async (user) => {
      try {
        await sendNotification(user.pushToken, title, body);

        // Update the lastNotificationSent timestamp for this user
        await User.findByIdAndUpdate(user._id, {
          lastNotificationSent: new Date(),
        });

        return { success: true, userId: user._id };
      } catch (error) {
        console.error(`Error sending notification to user ${user._id}:`, error);
        return { success: false, userId: user._id, error: error.message };
      }
    });

    const results = await Promise.all(notificationPromises);
    const successCount = results.filter((r) => r.success).length;
    const failureCount = results.length - successCount;

    res.status(200).json({
      message: `Notification sent to ${successCount} users successfully${
        failureCount > 0 ? `, ${failureCount} failed` : ""
      }${
        recentlyNotifiedCount > 0
          ? `, ${recentlyNotifiedCount} skipped (recently notified)`
          : ""
      }`,
      sentTo: users.map((user) => ({ id: user._id, name: user.name })),
      successCount,
      failureCount,
      skippedCount: recentlyNotifiedCount,
      results,
    });
  } catch (error) {
    console.error("Error sending notifications:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Endpoint to update user's anonymous mode
app.put("/users/:userId/anonymous", async (req, res) => {
  try {
    const { userId } = req.params;
    const { anonymous } = req.body;

    if (typeof anonymous !== "boolean") {
      return res
        .status(400)
        .json({ message: "Anonymous field must be a boolean" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { anonymous },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "Anonymous mode updated successfully",
      anonymous: updatedUser.anonymous,
    });
  } catch (error) {
    console.error("Error updating anonymous mode:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

// Endpoint to add priority to 1 on profiles that are viewed on the CMS
app.put("/set-priority/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { action } = req.body; // Optional: 'set' or 'remove', if not specified, toggle

    console.log("Updating priority for user:", userId);

    // Validate userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      console.log("Invalid user ID format:", userId);
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    // Find the user first to determine current priority
    const user = await User.findById(userId);

    if (!user) {
      console.log("User not found:", userId);
      return res.status(404).json({ message: "User not found" });
    }

    // Determine new priority value
    let newPriority = 1; // Default to setting priority

    if (action === "remove") {
      newPriority = 0;
    } else if (action === "set") {
      newPriority = 1;
    } else {
      // Toggle behavior - if no specific action provided
      newPriority = user.priority === 1 ? 0 : 1;
    }

    // Update the user's priority
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { priority: newPriority },
      { new: true }
    );

    console.log(
      `Priority ${newPriority === 1 ? "set" : "removed"} for user:`,
      updatedUser.name
    );
    return res.status(200).json({
      message:
        newPriority === 1
          ? "User priority set successfully"
          : "User priority removed successfully",
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        priority: updatedUser.priority,
      },
    });
  } catch (error) {
    console.error("Error updating user priority:", error);
    res.status(500).json({
      message: "Error updating user priority",
      error: error.message,
    });
  }
});

// Endpoint to flag or unflag a user
app.put("/users/:userId/flag", async (req, res) => {
  try {
    const { userId } = req.params;
    const { flagged, reason } = req.body;

    // Validate the userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    // Make sure flagged is a boolean
    if (typeof flagged !== "boolean") {
      return res
        .status(400)
        .json({ message: "Flagged parameter must be a boolean" });
    }

    // Update user's flagged status
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        flagged: flagged,
        flagReason: flagged ? reason || "Flagged by admin" : "",
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: flagged
        ? "User has been flagged successfully"
        : "User has been unflagged successfully",
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        flagged: updatedUser.flagged,
        flagReason: updatedUser.flagReason,
      },
    });
  } catch (error) {
    console.error("Error updating user flag status:", error);
    return res.status(500).json({
      message: "Error updating user flag status",
      error: error.message,
    });
  }
});

// Endpoint to get users with location data and their nearby users
app.get("/users-with-nearby", async (req, res) => {
  try {
    const {
      maxDistance = 50,
      limit = 20,
      page = 1,
      minNearbyCount = 0, // Minimum number of nearby users to include in results
    } = req.query;

    // Parse and validate parameters
    const maxDistanceMeters = parseFloat(maxDistance) * 1000; // Convert km to meters
    const userLimit = parseInt(limit, 10);
    const currentPage = parseInt(page, 10);
    const minNearby = parseInt(minNearbyCount, 10);
    const skip = (currentPage - 1) * userLimit;

    // Build the query for users with valid location data
    const query = {
      "location.coordinates": { $exists: true },
      "location.coordinates.0": { $ne: null, $exists: true },
      "location.coordinates.1": { $ne: null, $exists: true },
      pushToken: { $exists: true, $ne: null },
    };

    // Count total users matching the query for pagination info
    const totalUsers = await User.countDocuments(query);

    // Find users with valid location data with pagination
    const usersWithLocation = await User.find(query)
      .select("_id name email gender location profileImages pushToken")
      .skip(skip)
      .limit(userLimit)
      .lean();

    if (usersWithLocation.length === 0) {
      return res.status(404).json({
        message: "No users with location data found",
        pagination: {
          total: totalUsers,
          page: currentPage,
          limit: userLimit,
          pages: Math.ceil(totalUsers / userLimit),
        },
      });
    }

    // 2. For each user, find nearby users
    const usersWithNearbyData = await Promise.all(
      usersWithLocation.map(async (user) => {
        // Skip users with missing location data
        if (!user.location || !user.location.coordinates) {
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }

        const coordinates = user.location.coordinates;

        // Skip users with invalid coordinates
        if (!Array.isArray(coordinates) || coordinates.length !== 2) {
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }

        const [longitude, latitude] = coordinates;

        // Skip users with invalid coordinates values
        if (
          longitude === undefined ||
          latitude === undefined ||
          longitude === null ||
          latitude === null ||
          isNaN(longitude) ||
          isNaN(latitude) ||
          longitude === 0 ||
          latitude === 0
        ) {
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }

        try {
          // Build the gender query based on the current user's gender
          let genderQuery = {};

          // If the user's gender is male or female, look for opposite gender
          if (user.gender === "male") {
            genderQuery = { gender: "female" };
          } else if (user.gender === "female") {
            genderQuery = { gender: "male" };
          }
          // If the user's gender is not male or female (or undefined),
          // don't filter by gender to show all nearby users

          // Find nearby users
          const nearbyUsers = await User.aggregate([
            {
              $geoNear: {
                near: {
                  type: "Point",
                  coordinates: [longitude, latitude],
                },
                distanceField: "distance",
                maxDistance: maxDistanceMeters,
                spherical: true,
                query: {
                  _id: { $ne: user._id }, // Exclude the user themselves
                  ...genderQuery, // Apply gender filter if applicable
                  profileImages: { $exists: true, $not: { $size: 0 } },
                  flagged: { $ne: true },
                  pushToken: { $exists: true, $ne: null },
                },
                distanceMultiplier: 0.001, // Convert to kilometers
                key: "location",
              },
            },
            {
              $project: {
                _id: 1,
                name: 1,
                gender: 1,
                distance: 1,
                pushToken: 1,
                profileImages: { $slice: ["$profileImages", 1] }, // Only return first profile image
              },
            },
            { $limit: 20 }, // Limit nearby users per person
          ]);

          return {
            ...user,
            nearbyUsers,
            nearbyCount: nearbyUsers.length,
          };
        } catch (error) {
          console.error(
            `Error finding nearby users for user ${user._id}:`,
            error
          );
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }
      })
    );

    // 3. Filter and sort users by nearby count
    const filteredUsers = usersWithNearbyData
      .filter((user) => user.nearbyCount >= minNearby)
      .sort((a, b) => b.nearbyCount - a.nearbyCount);

    return res.status(200).json({
      pagination: {
        total: totalUsers,
        page: currentPage,
        limit: userLimit,
        pages: Math.ceil(totalUsers / userLimit),
      },
      totalUsersWithLocation: usersWithLocation.length,
      usersWithNearbyUsers: filteredUsers.length,
      users: filteredUsers,
    });
  } catch (error) {
    console.error("Error finding users with nearby data:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint for sending notifications about nearby users via email
app.post("/admin/send-nearby-email", async (req, res) => {
  try {
    const {
      userIds,
      customMessage,
      emailSubject,
      emailTemplate,
      nearbyUserCounts,
      ignoreWeeklyLimit,
    } = req.body;

    if (!userIds || !userIds.length || !customMessage) {
      return res.status(400).json({
        message: "User IDs array and customMessage are required",
      });
    }

    // Calculate one week ago to check for recent notifications
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    // Find users with email addresses who haven't received a notification in the last week
    let query = {
      _id: { $in: userIds },
      email: { $exists: true, $ne: null },
    };

    // Add weekly notification check unless explicitly ignored
    if (!ignoreWeeklyLimit) {
      query.$or = [
        { lastNotificationSent: { $exists: false } },
        { lastNotificationSent: { $lt: oneWeekAgo } },
      ];
    }

    const users = await User.find(query).select("_id name email");

    // Find filtered out users who recently received notifications
    const recentlyNotifiedCount = userIds.length - users.length;

    if (users.length === 0) {
      return res.status(404).json({
        message:
          recentlyNotifiedCount > 0
            ? `All selected users (${recentlyNotifiedCount}) were already notified within the last week`
            : "No users found with valid email addresses",
      });
    }

    console.log(
      `Starting to send emails to ${users.length} users (${recentlyNotifiedCount} filtered out due to recent notifications)`
    );

    // Send emails to all found users
    const emailPromises = users.map(async (user) => {
      const messageWithCount = customMessage.replace(
        "{count}",
        nearbyUserCounts && nearbyUserCounts[user._id.toString()]
          ? nearbyUserCounts[user._id.toString()].toString()
          : "0"
      );

      // Default template if none provided
      const defaultTemplate = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #6200ee;">Cuddles</h2>
          <p>Hello ${user.name || "there"},</p>
          <p>${messageWithCount}</p>
          <p>Open the Cuddles app to see who's nearby and make connections!</p>
          <p style="margin-top: 20px;">Warm regards,<br>The Cuddles Team</p>
        </div>
      `;

      // Process the custom template if provided
      let htmlContent = defaultTemplate;
      if (emailTemplate) {
        htmlContent = emailTemplate
          .replace("{name}", user.name || "there")
          .replace("{message}", messageWithCount)
          .replace(
            "{count}",
            nearbyUserCounts && nearbyUserCounts[user._id.toString()]
              ? nearbyUserCounts[user._id.toString()].toString()
              : "0"
          );
      }

      const mailOptions = {
        from: "Charlotte from Cuddles <cuddlesquery@gmail.com>",
        to: user.email,
        subject: emailSubject || "Nearby Users Alert",
        text: messageWithCount,
        html: htmlContent,
      };

      try {
        const emailResult = await transporter.sendMail(mailOptions);
        console.log(
          `Email sent to ${user.email} - Message ID: ${emailResult.messageId}`
        );

        // Update the lastNotificationSent timestamp for this user
        await User.findByIdAndUpdate(user._id, {
          lastNotificationSent: new Date(),
        });

        return {
          userId: user._id,
          email: user.email,
          success: true,
          messageId: emailResult.messageId,
        };
      } catch (error) {
        console.error(`Error sending email to ${user.email}:`, error);
        return {
          userId: user._id,
          email: user.email,
          success: false,
          error: error.message,
        };
      }
    });

    const emailResults = await Promise.all(emailPromises);

    // Count successes and failures
    const successCount = emailResults.filter((result) => result.success).length;
    const failureCount = emailResults.length - successCount;

    console.log(
      `Email sending complete: ${successCount} succeeded, ${failureCount} failed, ${recentlyNotifiedCount} skipped (recently notified)`
    );

    res.status(200).json({
      message: `Email notifications sent to ${successCount} users, failed for ${failureCount} users${
        recentlyNotifiedCount > 0
          ? `, ${recentlyNotifiedCount} skipped (recently notified)`
          : ""
      }`,
      results: emailResults,
      successCount,
      failureCount,
      skippedCount: recentlyNotifiedCount,
      emailsSent: successCount > 0,
    });
  } catch (error) {
    console.error("Error sending email notifications:", error);
    res.status(500).json({
      message: "Server error",
      error: error.message,
      emailsSent: false,
    });
  }
});

// Get users with filtering options for admin
app.get("/admin/users", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      hasImages,
      priority,
      flagged,
      email,
      name,
      userId,
      sortBy = "createdAt",
      sortOrder = -1,
    } = req.query;

    // Build query based on filters
    const query = {};

    // Filter by user ID if provided (exact match)
    if (userId) {
      // Check if it's a valid ObjectId format
      if (mongoose.Types.ObjectId.isValid(userId)) {
        query._id = new mongoose.Types.ObjectId(userId);
      } else {
        // If not a valid ObjectId, return empty result
        return res.status(200).json({
          users: [],
          totalUsers: 0,
          totalPages: 0,
          currentPage: parseInt(page),
        });
      }
    }

    // Filter by whether user has profile images
    if (hasImages === "true") {
      query.$expr = { $gt: [{ $size: "$profileImages" }, 0] };
    } else if (hasImages === "false") {
      query.$expr = { $eq: [{ $size: "$profileImages" }, 0] };
    }

    // Filter by priority
    if (priority !== undefined) {
      query.priority = parseInt(priority);
    }

    // Filter by flagged status
    if (flagged === "true") {
      query.flagged = true;
    } else if (flagged === "false") {
      query.flagged = false;
    }

    // Search by email (partial match)
    if (email) {
      query.email = { $regex: email, $options: "i" };
    }

    // Search by name (partial match)
    if (name) {
      query.name = { $regex: name, $options: "i" };
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Prepare sort options
    const sortOptions = {};
    sortOptions[sortBy] = parseInt(sortOrder);

    // Fetch users with query and pagination
    const users = await User.find(query)
      .select(
        "name email age gender profileImages flagged flagReason priority createdAt pushToken"
      )
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalUsers = await User.countDocuments(query);

    return res.status(200).json({
      users,
      totalUsers,
      totalPages: Math.ceil(totalUsers / parseInt(limit)),
      currentPage: parseInt(page),
    });
  } catch (error) {
    console.error("Error fetching filtered users:", error);
    res.status(500).json({
      message: "An error occurred while fetching users",
      error: error.message,
    });
  }
});

// Endpoint to upload verification selfie
app.post(
  "/verify/:userId/verification-selfie",
  upload.single("file"),
  async (req, res) => {
    const userId = req.params.userId;

    if (!req.file) {
      return res.status(400).json({ error: "No selfie image uploaded" });
    }

    console.log("userId", userId);

    try {
      // Upload the verification selfie to Cloudinary
      let selfieUrl;
      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          (uploadResult, error) => {
            if (error) {
              console.log("Cloudinary upload error:", error);
              return reject(error);
            }

            selfieUrl = uploadResult.secure_url;
            resolve(uploadResult); // Resolve the promise with the upload result
          }
        );
        uploadStream.end(req.file.buffer);
      });

      // Update the user's profile with the verification selfie URL

      console.log("selfieUrl", selfieUrl);
      if (selfieUrl) {
        const user = await User.findByIdAndUpdate(
          userId,
          {
            "profileVerification.selfieUrl": selfieUrl,
            "profileVerification.status": "pending",
            "profileVerification.submittedAt": new Date(),
          },
          { new: true }
        );

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
          message: "Verification selfie uploaded successfully",
          selfieUrl,
          status: "pending",
        });
      }
    } catch (error) {
      console.error("Verification selfie upload failed:", error);
      res.status(500).json({ error: "Verification selfie upload failed" });
    }
  }
);

// Endpoint to check verification status
app.get("/users/:userId/verification-status", async (req, res) => {
  const userId = req.params.userId;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({
      verificationStatus: user.profileVerification?.status || "not_submitted",
      selfieUrl: user.profileVerification?.selfieUrl || null,
      submittedAt: user.profileVerification?.submittedAt || null,
    });
  } catch (error) {
    console.error("Error checking verification status:", error);
    res.status(500).json({ error: "Failed to check verification status" });
  }
});

// Admin endpoint to update verification status
app.put("/admin/users/:userId/verification-status", async (req, res) => {
  const { userId } = req.params;
  const { status, adminId, notes } = req.body;

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }

  try {
    // Optional: Add admin authentication check here

    const user = await User.findByIdAndUpdate(
      userId,
      {
        "profileVerification.status": status,
        "profileVerification.reviewedAt": new Date(),
        "profileVerification.reviewedBy": adminId,
        "profileVerification.notes": notes,
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // If the user is approved, you might want to add a verified badge to their profile
    if (status === "approved") {
      // This uses the existing verified flag in the schema
      user.verified = true;
      await user.save();
    }

    return res.status(200).json({
      message: `Verification ${status}`,
      user: {
        id: user._id,
        name: user.name,
        profileVerification: user.profileVerification,
      },
    });
  } catch (error) {
    console.error("Error updating verification status:", error);
    res.status(500).json({ error: "Failed to update verification status" });
  }
});

// Endpoint to get all pending verifications
app.get("/admin/verifications/pending", async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Find users with pending verification status
    const pendingVerifications = await User.find({
      "profileVerification.status": "pending",
      "profileVerification.selfieUrl": { $ne: null },
    })
      .select(
        "_id name email profileVerification.selfieUrl profileVerification.submittedAt profileImages"
      )
      .sort({ "profileVerification.submittedAt": -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalCount = await User.countDocuments({
      "profileVerification.status": "pending",
      "profileVerification.selfieUrl": { $ne: null },
    });

    return res.status(200).json({
      verifications: pendingVerifications,
      totalVerifications: totalCount,
      totalPages: Math.ceil(totalCount / parseInt(limit)),
      currentPage: parseInt(page),
    });
  } catch (error) {
    console.error("Error fetching pending verifications:", error);
    res.status(500).json({ error: "Failed to fetch pending verifications" });
  }
});
