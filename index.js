const bodyParser = require("body-parser");
const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");
const cron = require("node-cron");
const User = require("./models/User");
const Report = require("./models/Report");
const SharedQuestion = require("./models/SharedQuestion");
const Question = require("./models/ Question");
const Message = require("./models/message");
const Event = require("./models/Event");
const EventMessage = require("./models/EventMessage");
const Notification = require("./models/Notification");
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
const { ObjectId } = require("mongodb");
const { updateUserCountry } = require("./Controllers/userController");

// Map to store user socket connections
const userSockets = new Map();

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

// Check if a string looks like a valid Expo push token (API-only; app may not send token)
const isValidExpoPushToken = (token) => {
  if (!token || typeof token !== "string") return false;
  const t = token.trim();
  return t.length > 0 && (t.startsWith("ExponentPushToken[") || t.startsWith("ExpoPushToken["));
};

// Helper function to create and send notifications
// In-app notification is always saved; push is best-effort only (no token or invalid token = no push, no failure)
const createNotification = async ({
  userId,
  type,
  title,
  message,
  eventId,
  eventName,
  actorId,
  actorName,
  actorImage,
}) => {
  try {
    // 1. Save to database (in-app notification) – always attempt
    const notification = new Notification({
      userId,
      type,
      title,
      message,
      eventId,
      eventName,
      actorId,
      actorName,
      actorImage,
    });
    await notification.save();

    // 2. Send push only if user has a valid Expo push token (optional; never fail the request)
    const user = await User.findById(userId).select("pushToken").lean();
    const token = user?.pushToken;
    if (isValidExpoPushToken(token)) {
      try {
        await sendNotification(token, title, message);
      } catch (pushError) {
        console.error(
          `[Notification] Failed to send push to user ${userId}:`,
          pushError?.message || pushError
        );
      }
    } else if (token) {
      console.log(`[Notification] User ${userId} has no valid Expo push token, skipping push`);
    }

    console.log(
      `[Notification] Created ${type} notification for user ${userId}`
    );
    return notification;
  } catch (error) {
    console.error("[Notification] Error creating notification:", error);
    throw error;
  }
};

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
  cloud_name: "dmqt8wnrd",
  api_key: "362393959313675",
  api_secret: "sL1aM1tebd3pkvXD51c37_0EERg",
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

http.listen(port, "0.0.0.0", () => {
  console.log(`Server is running on port ${port} and accessible from network`);
});

module.exports = mongoose;

// Socket.io connection
io.on("connection", (socket) => {
  // Listen for the join event and make the user join a specific room
  socket.on("join", ({ userId }) => {
    // Store the socket connection for this user
    userSockets.set(userId, socket.id);
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

  // ============================================================
  // EVENT CHAT SOCKET EVENTS (Open Tables)
  // ============================================================

  // Join event chat room
  socket.on("joinEventChat", async ({ userId, eventId }) => {
    try {
      // Verify user is a participant of the event
      const event = await Event.findById(eventId);
      if (!event) {
        socket.emit("joinEventChatError", {
          status: 404,
          message: "Event not found",
        });
        return;
      }

      const isParticipant = event.participants.some(
        (p) => p.userId.toString() === userId
      );
      if (!isParticipant) {
        socket.emit("joinEventChatError", {
          status: 403,
          message: "Only participants can join event chat",
        });
        return;
      }

      // Join the event chat room
      const roomName = `event_${eventId}`;
      socket.join(roomName);

      // Store the event room mapping for this socket
      if (!socket.eventRooms) {
        socket.eventRooms = new Set();
      }
      socket.eventRooms.add(roomName);

      socket.emit("joinEventChatSuccess", {
        status: 200,
        eventId,
        message: `Joined event chat successfully`,
      });

      console.log(`User ${userId} joined event chat: ${eventId}`);
    } catch (error) {
      console.error("Error joining event chat:", error);
      socket.emit("joinEventChatError", {
        status: 500,
        message: "Error joining event chat",
      });
    }
  });

  // Leave event chat room
  socket.on("leaveEventChat", ({ eventId }) => {
    const roomName = `event_${eventId}`;
    socket.leave(roomName);

    if (socket.eventRooms) {
      socket.eventRooms.delete(roomName);
    }

    socket.emit("leaveEventChatSuccess", {
      status: 200,
      eventId,
      message: "Left event chat successfully",
    });
  });

  // Send message to event chat
  socket.on(
    "sendEventMessage",
    async ({ senderId, eventId, message, type = "text", image }) => {
      try {
        // Verify user is a participant
        const event = await Event.findById(eventId);
        if (!event) {
          socket.emit("sendEventMessageError", {
            status: 404,
            message: "Event not found",
          });
          return;
        }

        const isParticipant = event.participants.some(
          (p) => p.userId.toString() === senderId
        );
        if (!isParticipant) {
          socket.emit("sendEventMessageError", {
            status: 403,
            message: "Only participants can send messages",
          });
          return;
        }

        // Create and save the message
        const newEventMessage = new EventMessage({
          eventId,
          senderId,
          message: type === "text" ? message : undefined,
          type,
          image: type === "image" ? image : undefined,
          createdAt: new Date(),
        });

        await newEventMessage.save();

        // Populate sender info
        const populatedMessage = await EventMessage.findById(
          newEventMessage._id
        ).populate("senderId", "name profileImages");

        // Emit to all users in the event room
        const roomName = `event_${eventId}`;
        io.to(roomName).emit("receiveEventMessage", {
          ...populatedMessage.toObject(),
          eventId,
        });

        console.log(`Event message sent to ${roomName}:`, message || "[image]");

        // Send push notifications to participants not in the room
        const sender = await User.findById(senderId).select("name");
        const participantsToNotify = await User.find({
          _id: {
            $in: event.participants
              .filter((p) => p.userId.toString() !== senderId)
              .map((p) => p.userId),
          },
          pushToken: { $exists: true, $ne: null },
        }).select("pushToken");

        const notificationMessage =
          type === "image"
            ? `${sender.name} sent an image`
            : message.length > 50
            ? `${message.substring(0, 50)}...`
            : message;

        for (const participant of participantsToNotify) {
          try {
            await sendNotification(
              participant.pushToken,
              `${event.title}`,
              `${sender.name}: ${notificationMessage}`
            );
          } catch (notifError) {
            console.error(
              "Error sending event message notification:",
              notifError
            );
          }
        }
      } catch (error) {
        console.error("Error sending event message:", error);
        socket.emit("sendEventMessageError", {
          status: 500,
          message: "Error sending message",
        });
      }
    }
  );

  // Send system message to event chat (e.g., "John joined the table")
  socket.on("sendEventSystemMessage", async ({ eventId, message }) => {
    try {
      const event = await Event.findById(eventId);
      if (!event) return;

      // Create system message
      const systemMessage = new EventMessage({
        eventId,
        senderId: event.hostId, // Use host as sender for system messages
        message,
        type: "system",
        createdAt: new Date(),
      });

      await systemMessage.save();

      // Emit to event room
      const roomName = `event_${eventId}`;
      io.to(roomName).emit("receiveEventMessage", {
        ...systemMessage.toObject(),
        eventId,
        isSystem: true,
      });
    } catch (error) {
      console.error("Error sending system message:", error);
    }
  });

  // Listen for incoming messages
  socket.on("sendMessage", async (data) => {
    const { senderId, receiverId, message, image, type } = data;
    console.log("Received message:", {
      senderId,
      receiverId,
      message,
      type,
      hasImage: !!image,
    });

    try {
      // Create a new message object
      const newMessage = {
        senderId,
        receiverId,
        message,
        type,
        image: type === "image" ? image : undefined,
        timestamp: new Date(),
        read: false,
      };

      // Save the message to the database
      const savedMessage = await Chat.create(newMessage);
      console.log("Message saved to database:", savedMessage);

      // Emit the message to the receiver if they are online
      const receiverSocketId = userSockets.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit("receiveMessage", savedMessage);
      }

      // Send push notification if receiver has a push token
      const receiver = await User.findById(receiverId);
      if (receiver?.pushToken) {
        const sender = await User.findById(senderId);
        const notificationMessage =
          type === "image" ? `${sender.name} sent you an image` : message;

        await sendPushNotification(
          receiver.pushToken,
          sender.name,
          notificationMessage
        );
      }

      // Update or create conversation for the sender
      await User.findByIdAndUpdate(
        senderId,
        {
          $push: {
            conversations: {
              receiverId,
              unreadMessagesCount: 0,
            },
          },
        },
        { upsert: true }
      );

      // Update or create conversation for the receiver
      await User.findByIdAndUpdate(
        receiverId,
        {
          $push: {
            conversations: {
              receiverId: senderId,
              unreadMessagesCount: 1,
            },
          },
        },
        { upsert: true }
      );
    } catch (error) {
      console.error("Error handling message:", error);
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
    // Remove the user's socket connection when they disconnect
    for (const [userId, socketId] of userSockets.entries()) {
      if (socketId === socket.id) {
        userSockets.delete(userId);
        break;
      }
    }
  });
});

// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, age, platform } = req.body;

    console.log(name, email, age);

    // Validate and normalize platform
    const validPlatforms = ["ios", "android", "unknown"];
    const normalizedPlatform = platform && validPlatforms.includes(platform.toLowerCase()) 
      ? platform.toLowerCase() 
      : "unknown";

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
      platform: normalizedPlatform,
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
  pool: true, // Use pooled connections
  maxConnections: 5, // Limit concurrent connections
  maxMessages: 100, // Limit messages per connection
  rateDelta: 1000, // How many messages to send per second
  rateLimit: 5, // Max number of messages per rateDelta
});

// Verify transporter configuration
transporter.verify(function (error, success) {
  if (error) {
    console.error("Transporter verification failed:", error);
  } else {
    console.log("Transporter is ready to send emails");
  }
});

// Helper function to send email with retry logic
const sendEmailWithRetry = async (mailOptions, maxRetries = 3) => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await transporter.sendMail(mailOptions);
      console.log(
        `Email sent successfully on attempt ${attempt}:`,
        result.messageId
      );
      return { success: true, messageId: result.messageId };
    } catch (error) {
      console.error(`Email send attempt ${attempt} failed:`, error);
      if (attempt === maxRetries) {
        return { success: false, error: error.message };
      }
      // Wait before retrying (exponential backoff)
      await new Promise((resolve) =>
        setTimeout(resolve, Math.pow(2, attempt) * 1000)
      );
    }
  }
  return { success: false, error: "Max retries exceeded" };
};

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
    console.log("Login attempt for email:", email);

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      console.log("no user ");
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Check if password is null
    if (!user.password) {
      console.log("User has no password set");
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

// Get relationship status between two users
app.get("/users/:userId/relationship/:otherUserId", async (req, res) => {
  try {
    const { userId, otherUserId } = req.params;

    if (
      !mongoose.Types.ObjectId.isValid(userId) ||
      !mongoose.Types.ObjectId.isValid(otherUserId)
    ) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const currentUser = await User.findById(userId).select(
      "Matches crushes recievedLikes"
    );
    const otherUser = await User.findById(otherUserId).select(
      "Matches crushes recievedLikes"
    );

    if (!currentUser || !otherUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if users are matched (mutual)
    const isMatched = currentUser.Matches.some(
      (id) => id.toString() === otherUserId
    );

    // Check if current user is following (has liked) the other user
    const isFollowing = currentUser.crushes.some(
      (id) => id.toString() === otherUserId
    );

    // Check if other user is following (has liked) the current user
    const isFollowedBy = otherUser.crushes.some(
      (id) => id.toString() === userId
    );

    return res.status(200).json({
      isMatched,
      isFollowing,
      isFollowedBy,
    });
  } catch (error) {
    console.error("Error fetching relationship status:", error);
    res.status(500).json({
      message: "Error fetching relationship status",
      error: error.message,
    });
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
      maxDistance = "50",
    } = req.query;

    const parsedMaxDistanceKm =
      maxDistance && !isNaN(parseFloat(maxDistance))
        ? parseFloat(maxDistance)
        : 50;
    const maxDistanceMeters = parsedMaxDistanceKm * 1000;

    // Filter out stale accounts (inactive for 60+ days)
    const staleAccountThreshold = new Date();
    staleAccountThreshold.setDate(staleAccountThreshold.getDate() - 60);

    // Input validation
    if (!mongoose.Types.ObjectId.isValid(userId) || !gender) {
      return res
        .status(400)
        .json({ message: "Invalid userId or missing gender" });
    }

    // Fetch only needed fields from current user
    const currentUser = await User.findById(userId)
      .select("gender Matches crushes profileDislikes location")
      .lean();

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Get user's country from their location object
    const userCountry = currentUser.location?.country;

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

    // Determine gender filter
    const genderFilter =
      gender === "both"
        ? currentUser.gender === "male"
          ? "female"
          : "male"
        : gender;

    // Base query criteria - optimized filters for better performance
    const baseMatch = {
      _id: { $nin: excludedObjectIds },
      gender: genderFilter,
      age: {
        $gte: minAge.toString(),
        $lte: maxAge.toString(),
      },
      profileImages: { $exists: true, $ne: [] },  // Faster than $not: { $size: 0 }
      anonymous: { $ne: true },                    // Simpler than $or with $exists
      flagged: { $ne: true },                      // Simpler than $and/$or with $exists
      // Filter out stale accounts using lastActiveAt or updatedAt as fallback
      $or: [
        { lastActiveAt: { $gte: staleAccountThreshold } },
        { 
          lastActiveAt: { $exists: false },
          updatedAt: { $gte: staleAccountThreshold }
        }
      ],
    };

    // Add lookingFor filter if provided
    if (lookingFor) {
      baseMatch.lookingFor = {
        $in: Array.isArray(lookingFor) ? lookingFor : [lookingFor],
      };
    }

    // Projection to limit returned fields for better performance
    const profileProjection = {
      _id: 1,
      name: 1,
      age: 1,
      gender: 1,
      profileImages: 1,
      description: 1,
      interests: 1,
      verified: 1,
      location: 1,
      occupation: 1,
      university: 1,
      preferences: 1,
      availability: 1,
      expectations: 1,
      lookingFor: 1,
      distance: 1,
    };

    let profiles = [];
    let hasLocation = false;

    // Function to get profiles with country filter - optimized with $facet
    const getProfilesWithCountry = async (countryFilter = true) => {
      const query = { ...baseMatch };
      if (countryFilter && userCountry) {
        // Only add country filter here when we want same country
        query["location.country"] = userCountry;
        console.log(`🌍 Attempting to find profiles from ${userCountry}`);
      } else {
        // When searching other countries, ensure we get profiles with a country set but not user's country
        query["location.country"] = { $exists: true, $ne: userCountry };
        console.log(`🌍 Searching for profiles from other countries`);
      }

      let countryProfiles = [];

      // Try to get nearby profiles first if location is provided
      if (longitude && latitude) {
        try {
          const nearbyProfiles = await User.aggregate([
            {
              $geoNear: {
                near: {
                  type: "Point",
                  coordinates: [parseFloat(longitude), parseFloat(latitude)],
                },
                distanceField: "distance",
                maxDistance: maxDistanceMeters,
                spherical: true,
                query: query,
                distanceMultiplier: 0.001,
                key: "location",
              },
            },
            { $project: profileProjection },
            { $limit: 20 },
          ]).option({ maxTimeMS: 5000 });

          countryProfiles = nearbyProfiles;
          hasLocation = true;
          console.log(
            `📍 Found ${countryProfiles.length} nearby profiles${
              countryFilter ? ` in ${userCountry}` : ""
            }`
          );
        } catch (error) {
          console.error("❌ Error in geospatial query:", error);
        }
      }

      // If we don't have enough profiles, use $facet to get both priority and newest in one query
      if (countryProfiles.length < 20) {
        const existingProfileIds = countryProfiles.map((p) => 
          mongoose.Types.ObjectId.isValid(p._id) ? new mongoose.Types.ObjectId(p._id) : p._id
        );
        const neededProfiles = 20 - countryProfiles.length;
        console.log(
          `🎯 Attempting to find ${neededProfiles} additional profiles${
            countryFilter ? ` in ${userCountry}` : ""
          } using $facet`
        );

        // Combine priority and random sample queries using $facet for single DB round-trip
        const facetResults = await User.aggregate([
          {
            $match: {
              _id: { $nin: [...excludedObjectIds, ...existingProfileIds] },
              ...query,
            },
          },
          {
            $facet: {
              priorityUsers: [
                { $match: { priority: 1 } },
                { $project: profileProjection },
                { $limit: neededProfiles },
              ],
              randomUsers: [
                { $sample: { size: neededProfiles } },  // Use $sample for better variety
                { $project: profileProjection },
              ],
            },
          },
        ]).option({ maxTimeMS: 5000 });

        if (facetResults.length > 0) {
          const { priorityUsers = [], randomUsers = [] } = facetResults[0];
          
          // Add priority users first
          const priorityIds = new Set();
          priorityUsers.forEach((p) => {
            const idStr = p._id.toString();
            if (!existingProfileIds.some((id) => id.toString() === idStr)) {
              countryProfiles.push(p);
              priorityIds.add(idStr);
            }
          });
          console.log(`⭐ Found ${priorityUsers.length} priority profiles`);

          // Add random users that aren't already included (using $sample for variety)
          const stillNeeded = 20 - countryProfiles.length;
          if (stillNeeded > 0) {
            const existingIds = new Set(countryProfiles.map((p) => p._id.toString()));
            const uniqueRandom = randomUsers.filter(
              (p) => !existingIds.has(p._id.toString())
            );
            countryProfiles.push(...uniqueRandom.slice(0, stillNeeded));
            console.log(`🎲 Added ${Math.min(uniqueRandom.length, stillNeeded)} random profiles`);
          }
        }

        console.log(`📊 Total profiles after $facet: ${countryProfiles.length}`);
      }

      return countryProfiles;
    };

    // First try to get profiles from the same country
    if (userCountry) {
      console.log(`\n🔍 Starting profile search for user in ${userCountry}`);
      profiles = await getProfilesWithCountry(true);
    }

    // If we don't have enough profiles from the same country, get profiles from other countries
    if (profiles.length < 20) {
      console.log(
        `\n⚠️ Not enough profiles from ${userCountry} (found ${profiles.length}), searching in other countries`
      );
      const otherCountryProfiles = await getProfilesWithCountry(false);

      // Filter out profiles we already have
      const existingProfileIds = new Set(profiles.map((p) => p._id.toString()));
      const newProfiles = otherCountryProfiles.filter(
        (p) => !existingProfileIds.has(p._id.toString())
      );

      const addedProfiles = newProfiles.slice(0, 20 - profiles.length);
      profiles.push(...addedProfiles);
      console.log(
        `➕ Added ${addedProfiles.length} profiles from other countries`
      );
      console.log(`📊 Final total profiles: ${profiles.length}`);
    }

    // Apply Fisher-Yates shuffle for proper randomness (in-place)
    for (let i = profiles.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [profiles[i], profiles[j]] = [profiles[j], profiles[i]];
    }
    const shuffledProfiles = profiles;

    // Calculate distances if location is provided
    if (hasLocation && shuffledProfiles.length > 0) {
      const parsedLong = parseFloat(longitude);
      const parsedLat = parseFloat(latitude);

      shuffledProfiles.forEach((profile) => {
        if (!profile.distance && profile.location?.coordinates) {
          profile.distance = calculateDistance(
            parsedLat,
            parsedLong,
            profile.location.coordinates[1],
            profile.location.coordinates[0]
          );
        }
      });
    }

    return res.status(200).json({
      profiles: shuffledProfiles,
      totalCount: shuffledProfiles.length,
      nearbyCount: shuffledProfiles.filter((p) => p.distance != null).length,
      userCountry: userCountry || "Unknown",
      sameCountryCount: shuffledProfiles.filter(
        (p) => p.location?.country === userCountry
      ).length,
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

    // Create persistent notification for the profile like
    try {
      await createNotification({
        userId: selectedUserId,
        type: "profile_like",
        title: "Someone wants to connect",
        message: `${currentUser.name || "A user"} wants to connect with you`,
        actorId: currentUserId,
        actorName: currentUser.name,
        actorImage: currentUser.profileImages?.[0] || null,
      });
    } catch (notifError) {
      console.error("Error creating profile like notification:", notifError);
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

    // Retrieve the current user with their interests for mutual matching
    const currentUser = await User.findById(userId)
      .select("recievedLikes profileDislikes interests location")
      .lean();

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Extract the IDs of the current user's disliked profiles
    const deslikedProfileId = (currentUser.profileDislikes || []).map(
      (profileDeslike) => profileDeslike.toString()
    );

    // Find users in the recievedLikes array but exclude disliked profiles
    const recievedLikesArray = await User.find({
      _id: { $in: currentUser.recievedLikes, $nin: deslikedProfileId },
    }).select(
      "_id name age gender profileImages location interests verified lastActiveAt updatedAt"
    ).lean();

    // Add mutual interests and format response for premium features
    const formattedLikes = recievedLikesArray.map((user) => {
      const userInterests = user.interests || [];
      const currentUserInterests = currentUser.interests || [];
      const mutualInterests = userInterests.filter(
        (interest) => currentUserInterests.includes(interest)
      );
      
      return {
        ...user,
        mutualInterests,
        mutualInterestsCount: mutualInterests.length,
      };
    });

    // Return the formatted received likes
    return res.status(200).json(formattedLikes);
  } catch (error) {
    console.error("Error fetching received likes:", error);
    res.status(500).json({ message: "Failed to retrieve the received likes" });
  }
});

// Super Wave - Premium feature to get noticed by nearby users
// Also triggers the like functionality (adds to recievedLikes and crushes)
app.post("/super-wave", async (req, res) => {
  try {
    const { senderId, receiverId } = req.body;

    if (!senderId || !receiverId) {
      return res.status(400).json({ message: "senderId and receiverId are required" });
    }

    const sender = await User.findById(senderId).select("name profileImages crushes").lean();
    const receiver = await User.findById(receiverId).select("pushToken recievedLikes").lean();

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if already liked to avoid duplicates
    const alreadyLiked = receiver.recievedLikes?.some(
      (id) => id.toString() === senderId.toString()
    );

    if (!alreadyLiked) {
      // Add sender to receiver's recievedLikes (like functionality)
      await User.findByIdAndUpdate(receiverId, {
        $addToSet: { recievedLikes: senderId },
      });

      // Add receiver to sender's crushes
      await User.findByIdAndUpdate(senderId, {
        $addToSet: { crushes: receiverId },
      });

      // Create profile_like notification (in-app only if no push token; never fail the wave)
      try {
        await createNotification({
          userId: receiverId,
          type: "profile_like",
          title: "Someone wants to connect",
          message: `${sender.name || "Someone"} sent you a Super Wave and likes your profile`,
          actorId: senderId,
          actorName: sender.name,
          actorImage: sender.profileImages?.[0] || null,
        });
      } catch (notifErr) {
        console.error("[Super Wave] profile_like notification failed (wave still succeeded):", notifErr?.message || notifErr);
      }
    }

    // Create super_wave notification (in-app only if no push token; never fail the wave)
    try {
      await createNotification({
        userId: receiverId,
        type: "super_wave",
        title: "Someone waved at you!",
        message: `${sender.name || "Someone"} sent you a Super Wave`,
        actorId: senderId,
        actorName: sender.name,
        actorImage: sender.profileImages?.[0] || null,
      });
    } catch (notifErr) {
      console.error("[Super Wave] super_wave notification failed (wave still succeeded):", notifErr?.message || notifErr);
    }

    console.log(`Super Wave sent from ${senderId} to ${receiverId}${alreadyLiked ? ' (already liked)' : ' (like added)'}`);
    res.status(200).json({ message: "Super Wave sent successfully" });
  } catch (error) {
    console.error("Error sending super wave:", error);
    res.status(500).json({ message: "Failed to send Super Wave" });
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
      type: msg.type || "text",
      image: msg.image, // Include the image field
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

    console.log("🔔 [PUSH TOKEN API] ========================================");
    console.log("🔔 [PUSH TOKEN API] Received request to save push token");
    console.log("🔔 [PUSH TOKEN API] UserId:", userId);
    console.log("🔔 [PUSH TOKEN API] Push Token:", pushToken);
    console.log("🔔 [PUSH TOKEN API] ========================================");

    if (!pushToken) {
      console.log("🔔 [PUSH TOKEN API] ❌ No pushToken provided in request body");
      return res.status(400).json({ message: "pushToken is required" });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { pushToken: pushToken },
      { new: true }
    );

    if (!user) {
      console.log("🔔 [PUSH TOKEN API] ❌ User not found:", userId);
      return res.status(404).json({ message: "user not found" });
    }

    console.log("🔔 [PUSH TOKEN API] ✅ SUCCESS! Push token saved for user:", user.name);
    console.log("🔔 [PUSH TOKEN API] Saved token:", user.pushToken);
    
    return res
      .status(200)
      .json({ message: "user pushToken updated successfully", savedToken: user.pushToken });
  } catch (error) {
    console.error("🔔 [PUSH TOKEN API] ❌ ERROR:", error.message);
    res
      .status(500)
      .json({ message: "Error updating users push token ", error: error.message });
  }
});

// Migration endpoint: Set all users without platform field to "unknown"
app.post("/admin/migrate-user-platforms", async (req, res) => {
  try {
    const result = await User.updateMany(
      { platform: { $exists: false } },
      { $set: { platform: "unknown" } }
    );
    res.json({ 
      message: "Migration completed", 
      updated: result.modifiedCount 
    });
  } catch (error) {
    console.error("Error migrating user platforms:", error);
    res.status(500).json({ error: error.message });
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

    // Validate coordinate bounds
    if (Math.abs(parsedLat) > 90 || Math.abs(parsedLong) > 180) {
      return res.status(400).json({ error: "Coordinates out of bounds" });
    }

    // Validate non-zero coordinates
    if (parsedLong === 0 && parsedLat === 0) {
      return res.status(400).json({ error: "Invalid zero coordinates" });
    }

    console.log(
      `📍 Updating location for user ${userId} - [${parsedLat}, ${parsedLong}]`
    );

    // Update user's location
    const user = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          location: {
            type: "Point",
            coordinates: [parsedLong, parsedLat], // MongoDB expects [longitude, latitude]
          },
        },
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update the user's country based on coordinates
    try {
      console.log("🌍 Attempting to update country...");
      const countryResult = await updateUserCountry(userId);
      console.log("✅ Country updated successfully:", countryResult);

      return res.status(200).json({
        message: "Location and country updated successfully",
        user,
        country: countryResult.country,
      });
    } catch (countryError) {
      console.error("❌ Error updating country:", countryError);
      // Return detailed error information
      return res.status(200).json({
        message: "Location updated successfully, but country update failed",
        user,
        countryError: {
          message: countryError.message,
          details: countryError.stack,
        },
      });
    }
  } catch (error) {
    console.error("❌ Error updating user's location:", error);
    return res.status(500).json({
      message: "Error updating user's location",
      error: error.message,
      stack: error.stack,
    });
  }
});

// fetch users that are close to each other due to location

app.get("/nearby-users", async (req, res) => {
  try {
    const { longitude, latitude, maxDistance, userId, limit } = req.query;
    console.log(longitude, latitude, maxDistance, userId, limit);

    if (!longitude || !latitude || !maxDistance) {
      return res
        .status(400)
        .json({ error: "Longitude, latitude, and maxDistance are required" });
    }

    // Parse coordinates and distance
    const parsedLong = parseFloat(longitude);
    const parsedLat = parseFloat(latitude);
    const parsedMaxDistance = parseInt(maxDistance) || 5000; // Default to 5km if not valid

    // Validate parsed coordinates
    if (isNaN(parsedLong) || isNaN(parsedLat)) {
      return res.status(400).json({ error: "Invalid coordinates format" });
    }

    console.log(
      `Searching for users within ${parsedMaxDistance}m of [${parsedLong}, ${parsedLat}]`
    );

    // Fetch user data upfront (like /profiles endpoint) - optimized for performance
    let excludedIds = [];
    let genderFilter = null;
    
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const currentUser = await User.findById(userId)
        .select("gender blockedBy")
        .lean();
      
      if (currentUser) {
        // Exclude current user
        excludedIds.push(new mongoose.Types.ObjectId(userId));
        
        // Exclude users who have blocked the current user
        if (currentUser.blockedBy?.length > 0) {
          excludedIds = excludedIds.concat(
            currentUser.blockedBy.map(id => new mongoose.Types.ObjectId(id))
          );
        }
        
        // iOS Cuddles specific: Filter by opposite gender (dating app)
        if (currentUser.gender === "male") {
          genderFilter = "female";
        } else if (currentUser.gender === "female") {
          genderFilter = "male";
        }
      }
    }

    // Optimized query filter - all exclusions included upfront (no $lookup needed)
    const queryFilter = {
      profileImages: { $exists: true, $ne: [] },
      "location.coordinates": { $exists: true, $ne: [0, 0] },
      flagged: { $ne: true },
      ...(excludedIds.length > 0 && { _id: { $nin: excludedIds } }),
      ...(genderFilter && { gender: genderFilter }), // iOS Cuddles: opposite gender only
    };

    // Simple aggregation pipeline - no expensive $lookup
    const nearbyUsers = await User.aggregate([
      {
        $geoNear: {
          near: {
            type: "Point",
            coordinates: [parsedLong, parsedLat],
          },
          distanceField: "distance",
          maxDistance: parsedMaxDistance,
          spherical: true,
          query: queryFilter,
          distanceMultiplier: 0.001, // Convert to kilometers
        },
      },
      {
        $project: {
          _id: 1,
          name: 1,
          age: 1,
          gender: 1,
          profileImages: { $slice: ["$profileImages", 1] }, // Only first image
          distance: 1,
          verified: 1,
          description: 1,
        },
      },
      {
        $limit: Math.min(parseInt(limit) || 20, 50), // Default 20, max 50
      },
    ]).option({ maxTimeMS: 5000 });

    console.log(`Found ${nearbyUsers.length} nearby users`);

    res.status(200).json({ 
      message: nearbyUsers.length > 0 ? "Nearby users found" : "No users found nearby",
      users: nearbyUsers 
    });
  } catch (error) {
    console.error("Error finding nearby users:", error);
    res
      .status(500)
      .json({ error: "Internal server error", details: error.message });
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
    const { title, body, userIds, ignoreWeeklyLimit } = req.body;

    if (!title || !body || !userIds || !Array.isArray(userIds)) {
      console.error("[Notification Endpoint] Invalid request parameters:", {
        title,
        body,
        userIds,
      });
      return res.status(400).json({ error: "Missing required fields" });
    }

    console.log(`[Notification Endpoint] Processing notification request:`, {
      title,
      body,
      userIdCount: userIds.length,
      ignoreWeeklyLimit,
    });

    // Build query to find users with push tokens
    const query = {
      _id: { $in: userIds.map((id) => new ObjectId(id)) },
      pushToken: { $exists: true, $ne: null },
    };

    // Add weekly limit check if not ignored
    if (!ignoreWeeklyLimit) {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      query.lastNotificationSent = { $lt: oneWeekAgo };
    }

    const users = await User.find(query);
    console.log(
      `[Notification Endpoint] Found ${users.length} eligible users with push tokens`
    );

    let successCount = 0;
    let failureCount = 0;
    const errors = [];

    for (const user of users) {
      try {
        console.log(`[Notification Endpoint] Sending notification to user:`, {
          userId: user._id,
          pushToken: user.pushToken.substring(0, 10) + "...",
        });

        await sendNotification(user.pushToken, title, body);

        // Update last notification timestamp
        await User.findByIdAndUpdate(user._id, {
          lastNotificationSent: new Date(),
        });

        successCount++;
        console.log(
          `[Notification Endpoint] Successfully sent notification to user ${user._id}`
        );
      } catch (error) {
        failureCount++;
        errors.push({
          userId: user._id,
          error: error.message,
        });
        console.error(
          `[Notification Endpoint] Failed to send notification to user ${user._id}:`,
          error
        );
      }
    }

    console.log(`[Notification Endpoint] Notification summary:`, {
      totalUsers: users.length,
      successCount,
      failureCount,
      errors: errors.length > 0 ? errors : undefined,
    });

    res.json({
      success: true,
      message: `Notifications sent successfully to ${successCount} users${
        failureCount > 0 ? `, ${failureCount} failed` : ""
      }`,
      stats: {
        totalUsers: users.length,
        successCount,
        failureCount,
        errors: errors.length > 0 ? errors : undefined,
      },
    });
  } catch (error) {
    console.error("[Notification Endpoint] Unexpected error:", error);
    res.status(500).json({ error: "Failed to send notifications" });
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

// Endpoint to get total count of flagged profiles
app.get("/admin/flagged-profiles/count", async (req, res) => {
  try {
    // Count all users where flagged is true
    const totalFlagged = await User.countDocuments({ flagged: true });

    return res.status(200).json({
      message: "Flagged profiles count retrieved successfully",
      totalFlagged: totalFlagged,
    });
  } catch (error) {
    console.error("Error counting flagged profiles:", error);
    return res.status(500).json({
      message: "Error counting flagged profiles",
      error: error.message,
    });
  }
});

// Endpoint to get all flagged profiles with pagination
app.get("/admin/flagged-profiles", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      sortBy = "createdAt",
      sortOrder = -1,
    } = req.query;

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Prepare sort options
    const sortOptions = {};
    sortOptions[sortBy] = parseInt(sortOrder);

    // Find all flagged users
    const flaggedUsers = await User.find({ flagged: true })
      .select(
        "name email age gender profileImages flagged flagReason createdAt pushToken location.country"
      )
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalFlagged = await User.countDocuments({ flagged: true });

    return res.status(200).json({
      users: flaggedUsers,
      totalUsers: totalFlagged,
      totalPages: Math.ceil(totalFlagged / parseInt(limit)),
      currentPage: parseInt(page),
      message: "Flagged profiles retrieved successfully",
    });
  } catch (error) {
    console.error("Error fetching flagged profiles:", error);
    return res.status(500).json({
      message: "Error fetching flagged profiles",
      error: error.message,
    });
  }
});

// Endpoint to bulk delete multiple users
app.post("/admin/users/bulk-delete", async (req, res) => {
  try {
    const { userIds } = req.body;

    // Validate input
    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        message: "User IDs array is required and must not be empty",
      });
    }

    console.log(`Attempting to delete ${userIds.length} users`);

    // Validate all IDs are valid ObjectIds
    const validIds = userIds.filter((id) =>
      mongoose.Types.ObjectId.isValid(id)
    );

    if (validIds.length !== userIds.length) {
      return res.status(400).json({
        message: "Some user IDs are invalid",
        invalidCount: userIds.length - validIds.length,
      });
    }

    // Convert to ObjectIds
    const objectIds = validIds.map((id) => new mongoose.Types.ObjectId(id));

    // Delete multiple users
    const result = await User.deleteMany({ _id: { $in: objectIds } });

    console.log(`Successfully deleted ${result.deletedCount} users`);

    return res.status(200).json({
      message: `Successfully deleted ${result.deletedCount} user(s)`,
      deletedCount: result.deletedCount,
      requestedCount: userIds.length,
    });
  } catch (error) {
    console.error("Error bulk deleting users:", error);
    return res.status(500).json({
      message: "Error deleting users",
      error: error.message,
    });
  }
});

// Endpoint to bulk unflag multiple users
app.post("/admin/users/bulk-unflag", async (req, res) => {
  try {
    const { userIds } = req.body;

    // Validate input
    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        message: "User IDs array is required and must not be empty",
      });
    }

    console.log(`Attempting to unflag ${userIds.length} users`);

    // Validate all IDs are valid ObjectIds
    const validIds = userIds.filter((id) =>
      mongoose.Types.ObjectId.isValid(id)
    );

    if (validIds.length !== userIds.length) {
      return res.status(400).json({
        message: "Some user IDs are invalid",
        invalidCount: userIds.length - validIds.length,
      });
    }

    // Convert to ObjectIds
    const objectIds = validIds.map((id) => new mongoose.Types.ObjectId(id));

    // Update multiple users to unflag them
    const result = await User.updateMany(
      { _id: { $in: objectIds } },
      { $set: { flagged: false, flagReason: "" } }
    );

    console.log(`Successfully unflagged ${result.modifiedCount} users`);

    return res.status(200).json({
      message: `Successfully unflagged ${result.modifiedCount} user(s)`,
      unflaggedCount: result.modifiedCount,
      requestedCount: userIds.length,
    });
  } catch (error) {
    console.error("Error bulk unflagging users:", error);
    return res.status(500).json({
      message: "Error unflagging users",
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
        const result = await sendEmailWithRetry(mailOptions);

        if (result.success) {
          // Update the lastNotificationSent timestamp for this user
          await User.findByIdAndUpdate(user._id, {
            lastNotificationSent: new Date(),
          });
        }

        return {
          userId: user._id,
          email: user.email,
          success: result.success,
          messageId: result.messageId,
          error: result.error,
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
      country,
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

    // Filter by country
    if (country) {
      query["location.country"] = { $regex: country, $options: "i" };
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Prepare sort options
    const sortOptions = {};
    sortOptions[sortBy] = parseInt(sortOrder);

    // Fetch users with query and pagination
    const users = await User.find(query)
      .select(
        "name email age gender profileImages flagged flagReason priority createdAt pushToken location.country"
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

// Add this function before the message handling code
const sendPushNotification = async (receiverId, title, body) => {
  try {
    // Find the user by their ID
    const user = await User.findById(receiverId);
    if (!user) {
      console.log(`[Push Notification] User not found with ID ${receiverId}`);
      return;
    }

    if (!user.pushToken) {
      console.log(
        `[Push Notification] No push token found for user ${receiverId}`
      );
      return;
    }

    // Validate the push token format
    if (
      !user.pushToken.startsWith("ExponentPushToken[") ||
      !user.pushToken.endsWith("]")
    ) {
      console.log(
        `[Push Notification] Invalid push token format for user ${receiverId}`
      );
      return;
    }

    console.log(
      `[Push Notification] Sending message notification to user ${receiverId}`
    );
    await sendNotification(user.pushToken, title, body);
    console.log(`[Push Notification] Successfully sent to user ${receiverId}`);
  } catch (error) {
    console.error(
      `[Push Notification] Error sending to user ${receiverId}:`,
      error
    );
  }
};

// Endpoint to get users with received likes for admin panel
app.get("/admin/users-with-likes", async (req, res) => {
  try {
    const {
      limit = 20,
      page = 1,
      minLikesCount = 0, // Minimum number of likes to include in results
    } = req.query;

    // Parse and validate parameters
    const userLimit = parseInt(limit, 10);
    const currentPage = parseInt(page, 10);
    const minLikes = parseInt(minLikesCount, 10);
    const skip = (currentPage - 1) * userLimit;

    // Build the query for users with received likes AND valid push tokens
    const query = {
      recievedLikes: { $exists: true, $not: { $size: 0 } },
      pushToken: { $exists: true, $ne: null, $ne: "" }, // Ensure pushToken exists, isn't null, and isn't empty
    };

    // Count total users matching the query for pagination info
    const totalUsers = await User.countDocuments(query);

    // Find users with received likes with pagination
    const usersWithLikes = await User.find(query)
      .select("_id name email gender profileImages pushToken recievedLikes")
      .skip(skip)
      .limit(userLimit)
      .lean();

    if (usersWithLikes.length === 0) {
      return res.status(404).json({
        message: "No users with received likes and push tokens found",
        pagination: {
          total: totalUsers,
          page: currentPage,
          limit: userLimit,
          pages: Math.ceil(totalUsers / userLimit),
        },
      });
    }

    // For each user, get detailed information about who liked them
    const usersWithLikesData = await Promise.all(
      usersWithLikes.map(async (user) => {
        try {
          // Get users who liked this person
          const likesDetails = await User.find(
            { _id: { $in: user.recievedLikes } },
            {
              _id: 1,
              name: 1,
              gender: 1,
              profileImages: { $slice: 1 },
              pushToken: 1,
            }
          ).lean();

          return {
            ...user,
            likedBy: likesDetails,
            likesCount: likesDetails.length,
          };
        } catch (error) {
          console.error(
            `Error fetching like details for user ${user._id}:`,
            error
          );
          return { ...user, likedBy: [], likesCount: 0 };
        }
      })
    );

    // Filter and sort users by likes count
    const filteredUsers = usersWithLikesData
      .filter((user) => user.likesCount >= minLikes)
      .sort((a, b) => b.likesCount - a.likesCount);

    return res.status(200).json({
      pagination: {
        total: totalUsers,
        page: currentPage,
        limit: userLimit,
        pages: Math.ceil(totalUsers / userLimit),
      },
      totalUsersWithLikes: usersWithLikes.length,
      usersWithFilteredLikes: filteredUsers.length,
      users: filteredUsers,
    });
  } catch (error) {
    console.error("Error finding users with received likes:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint to send push notifications to users with received likes
app.post("/admin/send-likes-notification", async (req, res) => {
  try {
    const {
      userIds,
      customMessage,
      emailSubject,
      emailTemplate,
      likesDetails,
      ignoreWeeklyLimit = false,
    } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        message: "User IDs are required and must be a non-empty array",
        success: false,
      });
    }

    if (!customMessage) {
      return res.status(400).json({
        message: "Custom message is required",
        success: false,
      });
    }

    // Track success and failure counts
    let successCount = 0;
    let failureCount = 0;
    let skippedCount = 0;
    let emailCount = 0;
    let pushCount = 0;

    // Process each user in the array
    await Promise.all(
      userIds.map(async (userId) => {
        try {
          // Get the user with their received likes
          const user = await User.findById(userId)
            .select("name email pushToken recievedLikes lastNotificationSent")
            .lean();

          if (!user) {
            console.log(`User ${userId} not found`);
            failureCount++;
            return;
          }

          // Check if we should skip due to weekly limit
          if (!ignoreWeeklyLimit && user.lastNotificationSent) {
            const lastSentDate = new Date(user.lastNotificationSent);
            const now = new Date();
            const daysSinceLastNotification = Math.floor(
              (now - lastSentDate) / (1000 * 60 * 60 * 24)
            );

            if (daysSinceLastNotification < 7) {
              console.log(
                `Skipping user ${userId} due to weekly notification limit`
              );
              skippedCount++;
              return;
            }
          }

          // Get the count of likes
          const likesCount = user.recievedLikes ? user.recievedLikes.length : 0;

          if (likesCount === 0) {
            console.log(`User ${userId} has no received likes, skipping`);
            skippedCount++;
            return;
          }

          // Track if any notification was sent
          let notificationSent = false;

          // Send push notification if the user has a push token
          if (user.pushToken) {
            try {
              // Customize the notification message
              const title = "You have new likes!";
              const body = customMessage.replace(
                "{likesCount}",
                likesCount.toString()
              );

              await sendNotification(user.pushToken, title, body);
              pushCount++;
              notificationSent = true;
              console.log(`Push notification sent to user ${userId}`);
            } catch (pushError) {
              console.error(
                `Error sending push notification to user ${userId}:`,
                pushError
              );
            }
          }

          // Send email if emailTemplate is provided and user has an email
          if (emailTemplate && emailSubject && user.email) {
            try {
              // Customize the email content
              const userName = user.name || "there";
              const emailBody = emailTemplate
                .replace(/{name}/g, userName)
                .replace(/{likesCount}/g, likesCount.toString());

              const mailOptions = {
                from: "Charlotte from Cuddles <cuddlesquery@gmail.com>",
                to: user.email,
                subject: emailSubject.replace(
                  /{likesCount}/g,
                  likesCount.toString()
                ),
                html: emailBody,
              };

              const emailResult = await sendEmailWithRetry(mailOptions);

              if (emailResult.success) {
                emailCount++;
                notificationSent = true;
                console.log(
                  `Email notification sent to user ${userId} at ${user.email}`
                );
              } else {
                console.error(
                  `Failed to send email to user ${userId}:`,
                  emailResult.error
                );
              }
            } catch (emailError) {
              console.error(
                `Error sending email to user ${userId}:`,
                emailError
              );
            }
          }

          // If any notification was sent, update the last notification timestamp
          if (notificationSent) {
            await User.findByIdAndUpdate(userId, {
              lastNotificationSent: new Date(),
            });

            // Increment success count
            successCount++;
          } else {
            failureCount++;
          }
        } catch (error) {
          console.error(`Error sending notification to user ${userId}:`, error);
          failureCount++;
        }
      })
    );

    // Return the response with counts
    return res.status(200).json({
      message: `Notifications processed: ${successCount} sent, ${failureCount} failed, ${skippedCount} skipped (${pushCount} push, ${emailCount} email)`,
      successCount,
      failureCount,
      skippedCount,
      pushCount,
      emailCount,
      success: successCount > 0,
    });
  } catch (error) {
    console.error("Error sending likes notifications:", error);
    return res.status(500).json({
      message: "Error sending likes notifications",
      error: error.message,
      success: false,
    });
  }
});

// Support email endpoint
app.post("/support-email", async (req, res) => {
  try {
    const { userId, subject, message, userEmail } = req.body;

    if (!userId || !subject || !message || !userEmail) {
      return res.status(400).json({
        message: "Missing required fields: userId, subject, message, userEmail",
      });
    }

    // Get user details
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const mailOptions = {
      from: "Cuddles Support <cuddlesquery@gmail.com>",
      to: "cuddlesquery@gmail.com", // Support team email
      subject: `Support Request: ${subject}`,
      html: `
        <h3>Support Request from Cuddles App</h3>
        <p><strong>User ID:</strong> ${userId}</p>
        <p><strong>User Email:</strong> ${userEmail}</p>
        <p><strong>User Name:</strong> ${user.name || "Not provided"}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, "<br>")}</p>
        <hr>
        <p><em>This email was sent from the Cuddles mobile app support form.</em></p>
      `,
    };

    const result = await sendEmailWithRetry(mailOptions);

    if (result.success) {
      // Send confirmation email to user
      const confirmationMailOptions = {
        from: "Cuddles Support <cuddlesquery@gmail.com>",
        to: userEmail,
        subject: "Support Request Received - Cuddles",
        html: `
          <h3>Thank you for contacting Cuddles Support!</h3>
          <p>We have received your support request and will get back to you as soon as possible.</p>
          <p><strong>Your request details:</strong></p>
          <p><strong>Subject:</strong> ${subject}</p>
          <p><strong>Message:</strong></p>
          <p>${message.replace(/\n/g, "<br>")}</p>
          <hr>
          <p>If you have any urgent concerns, please don't hesitate to reach out to us directly.</p>
          <p>Best regards,<br>The Cuddles Team</p>
        `,
      };

      await sendEmailWithRetry(confirmationMailOptions);

      res.status(200).json({
        message: "Support request sent successfully",
        success: true,
      });
    } else {
      res.status(500).json({
        message: "Failed to send support request",
        error: result.error,
        success: false,
      });
    }
  } catch (error) {
    console.error("Error sending support email:", error);
    res.status(500).json({
      message: "Error sending support request",
      error: error.message,
      success: false,
    });
  }
});

// ============================================================
// OPEN TABLES / EVENTS ENDPOINTS
// ============================================================

// Helper function to update event status based on time
const updateEventStatus = async (event) => {
  const now = new Date();
  let newStatus = event.status;

  if (event.status === "cancelled" || event.status === "ended") {
    return event;
  }

  // Check if event should be live
  if (event.startTime <= now && event.status === "upcoming") {
    newStatus = "live";
  }

  // Check if event should be ended
  if (event.endTime && event.endTime <= now) {
    newStatus = "ended";
  }

  // Check if event is full
  const goingCount = event.participants.filter(
    (p) => p.status === "going" || p.status === "checked_in"
  ).length;
  if (goingCount >= event.capacity && newStatus !== "ended") {
    newStatus = "full";
  } else if (goingCount < event.capacity && event.status === "full") {
    newStatus = event.startTime <= now ? "live" : "upcoming";
  }

  if (newStatus !== event.status) {
    event.status = newStatus;
    await event.save();
  }

  return event;
};

const cleanupExpiredEvents = async () => {
  try {
    const cutoffDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
    console.log(`[Event Cleanup] Starting cleanup at ${new Date().toISOString()}`);
    console.log(`[Event Cleanup] Deleting events with startTime before: ${cutoffDate.toISOString()}`);
    
    // Delete events where the meetup time (startTime) was more than 24 hours ago
    const result = await Event.deleteMany({
      startTime: { $lte: cutoffDate }
    });
    
    console.log(
      `[Event Cleanup] Cleanup completed. Removed ${result.deletedCount} event(s)`
    );
    
    return result;
  } catch (error) {
    console.error("[Event Cleanup] Error deleting old events:", error);
    throw error;
  }
};

// Schedule cleanup to run every hour
cron.schedule("0 * * * *", () => {
  console.log(`[Event Cleanup] Cron job triggered at ${new Date().toISOString()}`);
  cleanupExpiredEvents().catch((error) => {
    console.error("[Event Cleanup] Cron job error:", error);
  });
});

// Run cleanup on startup
console.log(`[Event Cleanup] Running initial cleanup on server startup`);
cleanupExpiredEvents().catch((error) => {
  console.error("[Event Cleanup] Initial cleanup error:", error);
});

// Expire pending suggestions that have passed their expiresAt time
const expireSuggestions = async () => {
  try {
    const now = new Date();
    console.log(`[Suggestion Expiry] Starting expiry check at ${now.toISOString()}`);

    // Find suggestions that have expired
    const expiredSuggestions = await Event.find({
      status: "suggested",
      expiresAt: { $lte: now },
    }).populate("hostId", "name pushToken");

    if (expiredSuggestions.length === 0) {
      return;
    }

    console.log(`[Suggestion Expiry] Found ${expiredSuggestions.length} expired suggestions`);

    for (const suggestion of expiredSuggestions) {
      try {
        // Mark as cancelled
        await Event.findByIdAndUpdate(suggestion._id, { status: "cancelled" });

        // Notify the suggester that their suggestion expired
        if (suggestion.hostId) {
          await createNotification({
            userId: suggestion.hostId._id,
            type: "suggestion_expired",
            title: "Suggestion Expired",
            message: `Your activity suggestion "${suggestion.title}" has expired without a response`,
            eventId: suggestion._id,
            eventName: suggestion.title,
          });
        }

        console.log(`[Suggestion Expiry] Expired suggestion: ${suggestion.title}`);
      } catch (notifError) {
        console.error(`[Suggestion Expiry] Error processing suggestion ${suggestion._id}:`, notifError);
      }
    }

    console.log(`[Suggestion Expiry] Processed ${expiredSuggestions.length} expired suggestions`);
  } catch (error) {
    console.error("[Suggestion Expiry] Error expiring suggestions:", error);
    throw error;
  }
};

// Schedule suggestion expiry to run every 15 minutes
cron.schedule("*/15 * * * *", () => {
  console.log(`[Suggestion Expiry] Cron job triggered at ${new Date().toISOString()}`);
  expireSuggestions().catch((error) => {
    console.error("[Suggestion Expiry] Cron job error:", error);
  });
});

// Run suggestion expiry on startup
console.log(`[Suggestion Expiry] Running initial expiry check on server startup`);
expireSuggestions().catch((error) => {
  console.error("[Suggestion Expiry] Initial expiry error:", error);
});

// Send reminder notifications for events starting within 1 hour
const sendEventReminders = async () => {
  try {
    const now = new Date();
    const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);

    // Find upcoming events starting within 1 hour that haven't had reminders sent
    const upcomingEvents = await Event.find({
      startTime: { $gte: now, $lte: oneHourFromNow },
      status: "upcoming",
      reminderSent: { $ne: true },
    }).populate("participants.userId", "name");

    if (upcomingEvents.length === 0) {
      return;
    }

    console.log(
      `[Event Reminder] Found ${upcomingEvents.length} events starting soon`
    );

    for (const event of upcomingEvents) {
      // Calculate time until event starts
      const minutesUntilStart = Math.round(
        (event.startTime - now) / (1000 * 60)
      );
      const timeString =
        minutesUntilStart > 60
          ? "1 hour"
          : minutesUntilStart > 1
          ? `${minutesUntilStart} minutes`
          : "soon";

      // Send reminder to all participants
      for (const participant of event.participants) {
        try {
          await createNotification({
            userId: participant.userId._id || participant.userId,
            type: "event_reminder",
            title: "Event starting soon",
            message: `Your event "${event.title}" starts in ${timeString}`,
            eventId: event._id,
            eventName: event.title,
          });
        } catch (notifError) {
          console.error(
            `Error creating reminder notification for user ${participant.userId}:`,
            notifError
          );
        }
      }

      // Mark event as reminder sent
      event.reminderSent = true;
      await event.save();

      console.log(
        `[Event Reminder] Sent reminders for event "${event.title}" to ${event.participants.length} participants`
      );
    }
  } catch (error) {
    console.error("[Event Reminder] Error sending reminders:", error);
  }
};

// Schedule event reminders to run every 15 minutes
cron.schedule("*/15 * * * *", sendEventReminders);
// Run once on startup
sendEventReminders().catch((error) =>
  console.error("[Event Reminder] Error on startup:", error)
);

// Create new event
app.post("/events", async (req, res) => {
  try {
    const {
      hostId,
      title,
      description,
      location,
      coverImage,
      startTime,
      endTime,
      capacity,
      tags,
      status,
      suggestedToUserId,
      suggestedToUserIds, // Array for group invites
      expiresAt,
    } = req.body;

    // Validate required fields
    if (!hostId || !title || !location || !startTime) {
      return res.status(400).json({
        message: "Missing required fields: hostId, title, location, startTime",
      });
    }

    // Validate location structure
    if (!location.coordinates || !location.name) {
      return res.status(400).json({
        message: "Location must include coordinates and name",
      });
    }

    // Validate startTime is in the future
    if (new Date(startTime) <= new Date()) {
      return res.status(400).json({
        message: "Start time must be in the future",
      });
    }

    // Validate capacity
    if (capacity && (capacity < 1 || capacity > 10)) {
      return res.status(400).json({
        message: "Capacity must be between 1 and 10",
      });
    }

    // Check if host exists
    const host = await User.findById(hostId);
    if (!host) {
      return res.status(404).json({ message: "Host user not found" });
    }

    // Check if this is a suggestion (single or group)
    const isGroupSuggestion = status === "suggested" && Array.isArray(suggestedToUserIds) && suggestedToUserIds.length > 0;
    const isSingleSuggestion = status === "suggested" && suggestedToUserId && !isGroupSuggestion;
    const isSuggestion = isGroupSuggestion || isSingleSuggestion;

    // Validate target users for suggestions
    let targetUsers = [];
    if (isGroupSuggestion) {
      targetUsers = await User.find({ _id: { $in: suggestedToUserIds } }).select("_id name profileImages");
      if (targetUsers.length !== suggestedToUserIds.length) {
        return res.status(404).json({ message: "One or more suggested users not found" });
      }
    } else if (isSingleSuggestion) {
      const targetUser = await User.findById(suggestedToUserId);
      if (!targetUser) {
        return res.status(404).json({ message: "Suggested user not found" });
      }
      targetUsers = [targetUser];
    }

    // Create the event
    const newEvent = new Event({
      hostId,
      title,
      description,
      location: {
        type: "Point",
        coordinates: location.coordinates,
        name: location.name,
        address: location.address,
      },
      coverImage,
      startTime: new Date(startTime),
      endTime: endTime ? new Date(endTime) : null,
      capacity: capacity || 6,
      tags: tags || [],
      // For suggestions, don't add participants yet (wait for acceptance)
      participants: isSuggestion ? [] : [
        {
          userId: hostId,
          status: "going",
          joinedAt: new Date(),
        },
      ],
      status: isSuggestion ? "suggested" : "upcoming",
      suggestedToUserId: isSingleSuggestion ? suggestedToUserId : undefined,
      suggestedToUserIds: isGroupSuggestion ? suggestedToUserIds : undefined,
      expiresAt: isSuggestion && expiresAt ? new Date(expiresAt) : undefined,
    });

    await newEvent.save();

    // Populate host info for response (wrap in try-catch to ensure response is sent)
    let populatedEvent;
    try {
      populatedEvent = await Event.findById(newEvent._id).populate(
        "hostId",
        "name profileImages"
      );
    } catch (populateError) {
      console.error("Error populating event:", populateError);
      // If populate fails, use the event without population
      populatedEvent = newEvent;
    }

    // Send success response immediately after event is created
    const suggestionCount = targetUsers.length;
    res.status(201).json({
      message: isSuggestion 
        ? (suggestionCount > 1 ? `Activity suggestion sent to ${suggestionCount} people` : "Activity suggestion sent")
        : "Event created successfully",
      event: populatedEvent,
    });

    // Handle notifications after response is sent
    setImmediate(async () => {
      try {
        if (isSuggestion && targetUsers.length > 0) {
          // Send notification to all suggested users
          for (const targetUser of targetUsers) {
            try {
              await createNotification({
                userId: targetUser._id,
                type: "activity_suggestion",
                title: "Activity Suggestion",
                message: isGroupSuggestion 
                  ? `${host.name} invited you and ${suggestionCount - 1} others to "${title}"`
                  : `${host.name} wants to do "${title}" with you`,
                eventId: newEvent._id,
                eventName: title,
                actorId: hostId,
                actorName: host.name,
                actorImage: host.profileImages?.[0],
              });
              console.log(`[Suggestion] Sent activity suggestion notification to ${targetUser.name}`);
            } catch (notifError) {
              console.error(`Error creating suggestion notification for user ${targetUser._id}:`, notifError);
            }
          }
          console.log(`[Suggestion] Completed sending ${suggestionCount} suggestion notifications`);
        } else {
          // Regular event - notify nearby users (within 50km)
          const [eventLng, eventLat] = location.coordinates;
          const maxDistanceMeters = 50000; // 50km

          // Find nearby users with push tokens (exclude the host)
          const nearbyUsers = await User.aggregate([
            {
              $geoNear: {
                near: {
                  type: "Point",
                  coordinates: [eventLng, eventLat],
                },
                distanceField: "distance",
                maxDistance: maxDistanceMeters,
                spherical: true,
                query: {
                  _id: { $ne: new mongoose.Types.ObjectId(hostId) },
                  pushToken: { $exists: true, $ne: null },
                },
              },
            },
            { $limit: 50 }, // Limit to 50 users
            { $project: { _id: 1, name: 1 } },
          ]);

          console.log(
            `[Event Nearby] Found ${nearbyUsers.length} users near new event "${title}"`
          );

          // Create notifications for nearby users
          for (const nearbyUser of nearbyUsers) {
            try {
              await createNotification({
                userId: nearbyUser._id,
                type: "event_nearby",
                title: "New event nearby",
                message: `A new event "${title}" is happening near you`,
                eventId: newEvent._id,
                eventName: title,
                actorId: hostId,
                actorName: host.name,
              });
            } catch (notifError) {
              console.error(
                `Error creating nearby notification for user ${nearbyUser._id}:`,
                notifError
              );
            }
          }
        }
      } catch (notifyError) {
        console.error("Error sending notifications:", notifyError);
      }
    });
  } catch (error) {
    console.error("Error creating event:", error);
    if (error.status) {
      return res.status(error.status).json({ message: error.message });
    }
    res.status(500).json({
      message: "Error creating event",
      error: error.message,
    });
  }
});

// Update event (host only)
app.put("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;
    const {
      userId,
      title,
      description,
      startTime,
      endTime,
      capacity,
      tags,
      coverImage,
    } = req.body;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if user is the host
    if (event.hostId.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Only the host can update this event" });
    }

    // Don't allow updates to ended or cancelled events
    if (event.status === "ended" || event.status === "cancelled") {
      return res
        .status(400)
        .json({ message: "Cannot update ended or cancelled events" });
    }

    // Update allowed fields
    if (title) event.title = title;
    if (description !== undefined) event.description = description;
    if (startTime) event.startTime = new Date(startTime);
    if (endTime) event.endTime = new Date(endTime);
    if (capacity && capacity >= 1 && capacity <= 10) event.capacity = capacity;
    if (tags) event.tags = tags;
    if (coverImage !== undefined) event.coverImage = coverImage;

    await event.save();

    // Notify all participants (except host) about the update
    const participantIds = event.participants
      .map((p) => p.userId.toString())
      .filter((id) => id !== userId);

    for (const participantId of participantIds) {
      try {
        await createNotification({
          userId: participantId,
          type: "event_updated",
          title: "Event updated",
          message: `"${event.title}" has been updated by the host`,
          eventId: event._id,
          eventName: event.title,
        });
      } catch (notifError) {
        console.error("Error creating update notification:", notifError);
      }
    }

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    res.status(200).json({
      message: "Event updated successfully",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error updating event:", error);
    res.status(500).json({
      message: "Error updating event",
      error: error.message,
    });
  }
});

// Cancel/Delete event (host only)
app.delete("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId } = req.body;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if user is the host
    if (event.hostId.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Only the host can cancel this event" });
    }

    // Store event info for notifications before deletion
    const eventTitle = event.title;
    const participantIds = event.participants
      .map((p) => p.userId.toString())
      .filter((id) => id !== userId);

    // Notify all participants (except host) about cancellation before deleting
    for (const participantId of participantIds) {
      try {
        await createNotification({
          userId: participantId,
          type: "event_cancelled",
          title: "Event cancelled",
          message: `The event "${eventTitle}" has been cancelled`,
          eventId: event._id,
          eventName: eventTitle,
        });
      } catch (notifError) {
        console.error("Error creating cancel notification:", notifError);
      }
    }

    // Delete all event chat messages
    try {
      const deleteMessagesResult = await EventMessage.deleteMany({ eventId });
      console.log(
        `[Event Delete] Deleted ${deleteMessagesResult.deletedCount} messages for event ${eventId}`
      );
    } catch (messageError) {
      console.error("Error deleting event messages:", messageError);
    }

    // Delete the event itself
    await Event.findByIdAndDelete(eventId);

    console.log(`[Event Delete] Successfully deleted event ${eventId}`);

    res.status(200).json({ message: "Event cancelled and deleted successfully" });
  } catch (error) {
    console.error("Error cancelling event:", error);
    res.status(500).json({
      message: "Error cancelling event",
      error: error.message,
    });
  }
});

// Get nearby events
app.get("/events/nearby", async (req, res) => {
  try {
    const { latitude, longitude, radius = 50000, userId } = req.query;

    if (!latitude || !longitude) {
      return res.status(400).json({
        message: "Latitude and longitude are required",
      });
    }

    const parsedLat = parseFloat(latitude);
    const parsedLng = parseFloat(longitude);
    const parsedRadius = parseInt(radius);

    if (isNaN(parsedLat) || isNaN(parsedLng)) {
      return res.status(400).json({ message: "Invalid coordinates format" });
    }

    // Get blocked users list if userId provided
    let blockedUserIds = [];
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const currentUser = await User.findById(userId).select("blockedBy");
      if (currentUser) {
        blockedUserIds = currentUser.blockedBy.map((id) => id.toString());
      }
    }

    const nearbyEvents = await Event.aggregate([
      {
        $geoNear: {
          near: {
            type: "Point",
            coordinates: [parsedLng, parsedLat],
          },
          distanceField: "distance",
          maxDistance: parsedRadius,
          spherical: true,
          query: {
            status: { $in: ["upcoming", "live", "full"] },
            hostId: {
              $nin: blockedUserIds.map((id) => new mongoose.Types.ObjectId(id)),
            },
          },
          distanceMultiplier: 0.001, // Convert to km
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "hostId",
          foreignField: "_id",
          as: "host",
          pipeline: [{ $project: { name: 1, profileImages: 1 } }],
        },
      },
      {
        $unwind: "$host",
      },
      {
        $addFields: {
          participantCount: { $size: "$participants" },
        },
      },
      {
        $sort: { startTime: 1 },
      },
      {
        $limit: 50,
      },
    ]);

    // Update status for each event if needed
    for (let event of nearbyEvents) {
      const eventDoc = await Event.findById(event._id);
      if (eventDoc) {
        await updateEventStatus(eventDoc);
      }
    }

    res.status(200).json({
      message: "Nearby events found",
      events: nearbyEvents,
      count: nearbyEvents.length,
    });
  } catch (error) {
    console.error("Error fetching nearby events:", error);
    res.status(500).json({
      message: "Error fetching nearby events",
      error: error.message,
    });
  }
});

// Search events by title/tags
app.get("/events/search", async (req, res) => {
  try {
    const {
      q,
      tags,
      latitude,
      longitude,
      userId,
      page = 1,
      limit = 20,
    } = req.query;

    const query = {
      status: { $in: ["upcoming", "live", "full"] },
    };

    // Search by title or description
    if (q) {
      query.$or = [
        { title: { $regex: q, $options: "i" } },
        { description: { $regex: q, $options: "i" } },
        { "location.name": { $regex: q, $options: "i" } },
      ];
    }

    // Filter by tags
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(",");
      query.tags = { $in: tagArray };
    }

    // Exclude blocked users
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const currentUser = await User.findById(userId).select("blockedBy");
      if (currentUser && currentUser.blockedBy.length > 0) {
        query.hostId = { $nin: currentUser.blockedBy };
      }
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    let events;

    // If location provided, sort by distance
    if (latitude && longitude) {
      const parsedLat = parseFloat(latitude);
      const parsedLng = parseFloat(longitude);

      events = await Event.aggregate([
        {
          $geoNear: {
            near: {
              type: "Point",
              coordinates: [parsedLng, parsedLat],
            },
            distanceField: "distance",
            spherical: true,
            query: query,
            distanceMultiplier: 0.001,
          },
        },
        { $skip: skip },
        { $limit: parseInt(limit) },
        {
          $lookup: {
            from: "users",
            localField: "hostId",
            foreignField: "_id",
            as: "host",
            pipeline: [{ $project: { name: 1, profileImages: 1 } }],
          },
        },
        { $unwind: "$host" },
      ]);
    } else {
      events = await Event.find(query)
        .populate("hostId", "name profileImages")
        .sort({ startTime: 1 })
        .skip(skip)
        .limit(parseInt(limit));
    }

    const total = await Event.countDocuments(query);

    res.status(200).json({
      events,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error searching events:", error);
    res.status(500).json({
      message: "Error searching events",
      error: error.message,
    });
  }
});

// Get user's events (hosting + joined)
app.get("/events/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { type = "all" } = req.query; // 'hosting', 'joined', 'all'

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    let query = {};

    if (type === "hosting") {
      query = { hostId: userId };
    } else if (type === "joined") {
      query = {
        "participants.userId": userId,
        hostId: { $ne: userId },
      };
    } else {
      query = {
        $or: [{ hostId: userId }, { "participants.userId": userId }],
      };
    }

    const events = await Event.find(query)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages")
      .sort({ startTime: -1 });

    // Update statuses
    for (let event of events) {
      await updateEventStatus(event);
    }

    res.status(200).json({
      events,
      count: events.length,
    });
  } catch (error) {
    console.error("Error fetching user events:", error);
    res.status(500).json({
      message: "Error fetching user events",
      error: error.message,
    });
  }
});

// Join event
app.post("/events/:eventId/join", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, status = "interested" } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const joiningUser = await User.findById(userId).select("name");
    if (!joiningUser) {
      return res.status(404).json({ message: "User not found" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Update event status first
    await updateEventStatus(event);

    // Check if event is joinable
    if (event.status === "ended" || event.status === "cancelled") {
      return res
        .status(400)
        .json({ message: "Cannot join ended or cancelled events" });
    }

    if (event.status === "full") {
      return res.status(400).json({ message: "Event is full" });
    }

    // Check if user is already a participant
    const existingParticipant = event.participants.find(
      (p) => p.userId.toString() === userId
    );
    if (existingParticipant) {
      return res
        .status(400)
        .json({ message: "You have already joined this event" });
    }

    // Check if user is blocked by host
    const host = await User.findById(event.hostId).select("blockedBy");
    if (host && host.blockedBy.includes(userId)) {
      return res.status(403).json({ message: "You cannot join this event" });
    }

    // Add user as participant
    event.participants.push({
      userId,
      status: status,
      joinedAt: new Date(),
    });

    // Update event status if now full
    const goingCount = event.participants.filter(
      (p) => p.status === "going" || p.status === "checked_in"
    ).length;
    if (goingCount >= event.capacity) {
      event.status = "full";
    }

    await event.save();

    // Create notification for host (stored in DB + push notification)
    try {
      await createNotification({
        userId: event.hostId,
        type: "event_joined",
        title: "New participant joined",
        message: `${joiningUser.name} joined your event "${event.title}"`,
        eventId: event._id,
        eventName: event.title,
        actorId: userId,
        actorName: joiningUser.name,
      });
    } catch (notifError) {
      console.error("Error creating join notification:", notifError);
    }

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    res.status(200).json({
      message: "Successfully joined event",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error joining event:", error);
    if (error.status) {
      return res.status(error.status).json({ message: error.message });
    }
    res.status(500).json({
      message: "Error joining event",
      error: error.message,
    });
  }
});

// Update RSVP status
app.put("/events/:eventId/rsvp", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, status } = req.body;

    if (!["interested", "going", "checked_in"].includes(status)) {
      return res.status(400).json({
        message: "Invalid status. Must be: interested, going, or checked_in",
      });
    }

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Find participant
    const participantIndex = event.participants.findIndex(
      (p) => p.userId.toString() === userId
    );
    if (participantIndex === -1) {
      return res
        .status(404)
        .json({ message: "You are not a participant of this event" });
    }

    // Update status
    event.participants[participantIndex].status = status;

    // Update event status if needed
    const goingCount = event.participants.filter(
      (p) => p.status === "going" || p.status === "checked_in"
    ).length;

    if (goingCount >= event.capacity && event.status !== "ended") {
      event.status = "full";
    } else if (goingCount < event.capacity && event.status === "full") {
      const now = new Date();
      event.status = event.startTime <= now ? "live" : "upcoming";
    }

    await event.save();

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    res.status(200).json({
      message: "RSVP status updated",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error updating RSVP:", error);
    res.status(500).json({
      message: "Error updating RSVP",
      error: error.message,
    });
  }
});

// Check-in to event (validates location)
app.post("/events/:eventId/check-in", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, latitude, longitude } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    if (!latitude || !longitude) {
      return res
        .status(400)
        .json({ message: "Location is required for check-in" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Update event status
    await updateEventStatus(event);

    // Check if event is live
    if (event.status !== "live" && event.status !== "full") {
      return res.status(400).json({
        message: "Check-in is only available for live events",
      });
    }

    // Find participant
    const participantIndex = event.participants.findIndex(
      (p) => p.userId.toString() === userId
    );
    if (participantIndex === -1) {
      return res
        .status(404)
        .json({ message: "You are not a participant of this event" });
    }

    // Calculate distance using existing helper
    const userLat = parseFloat(latitude);
    const userLng = parseFloat(longitude);
    const eventLat = event.location.coordinates[1];
    const eventLng = event.location.coordinates[0];

    const distance = calculateDistance(userLat, userLng, eventLat, eventLng);
    const distanceInMeters = distance * 1000;

    if (distanceInMeters > event.checkInRadius) {
      return res.status(400).json({
        message: `You must be within ${
          event.checkInRadius
        }m of the event location to check in. You are ${Math.round(
          distanceInMeters
        )}m away.`,
      });
    }

    // Update participant status to checked_in
    event.participants[participantIndex].status = "checked_in";
    await event.save();

    // Notify other participants
    const otherParticipants = await User.find({
      _id: {
        $in: event.participants
          .filter((p) => p.userId.toString() !== userId)
          .map((p) => p.userId),
      },
      pushToken: { $exists: true, $ne: null },
    }).select("pushToken");

    const checkedInUser = await User.findById(userId).select("name");

    for (const participant of otherParticipants) {
      try {
        await sendNotification(
          participant.pushToken,
          "Participant Checked In",
          `${checkedInUser.name} has arrived at "${event.title}"`
        );
      } catch (notifError) {
        console.error("Error sending notification:", notifError);
      }
    }

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    res.status(200).json({
      message: "Successfully checked in",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error checking in:", error);
    res.status(500).json({
      message: "Error checking in",
      error: error.message,
    });
  }
});

// Leave event
app.delete("/events/:eventId/leave", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Host cannot leave their own event
    if (event.hostId.toString() === userId) {
      return res.status(400).json({
        message: "Host cannot leave the event. Cancel the event instead.",
      });
    }

    // Find and remove participant
    const participantIndex = event.participants.findIndex(
      (p) => p.userId.toString() === userId
    );
    if (participantIndex === -1) {
      return res
        .status(404)
        .json({ message: "You are not a participant of this event" });
    }

    event.participants.splice(participantIndex, 1);

    // Update event status if it was full
    if (event.status === "full") {
      const now = new Date();
      event.status = event.startTime <= now ? "live" : "upcoming";
    }

    await event.save();

    res.status(200).json({ message: "Successfully left event" });
  } catch (error) {
    console.error("Error leaving event:", error);
    res.status(500).json({
      message: "Error leaving event",
      error: error.message,
    });
  }
});

// Remove participant (host only)
app.delete("/events/:eventId/participants/:participantId", async (req, res) => {
  try {
    const { eventId, participantId } = req.params;
    const { userId } = req.body; // Host's userId

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(participantId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if requester is the host
    if (event.hostId.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Only the host can remove participants" });
    }

    // Cannot remove self (host)
    if (participantId === userId) {
      return res
        .status(400)
        .json({ message: "Host cannot be removed from the event" });
    }

    // Find and remove participant
    const participantIndex = event.participants.findIndex(
      (p) => p.userId.toString() === participantId
    );
    if (participantIndex === -1) {
      return res
        .status(404)
        .json({ message: "Participant not found in this event" });
    }

    event.participants.splice(participantIndex, 1);

    // Update event status if it was full
    if (event.status === "full") {
      const now = new Date();
      event.status = event.startTime <= now ? "live" : "upcoming";
    }

    await event.save();

    // Notify removed participant
    const removedUser = await User.findById(participantId).select("pushToken");
    if (removedUser && removedUser.pushToken) {
      try {
        await sendNotification(
          removedUser.pushToken,
          "Removed from Event",
          `You have been removed from "${event.title}"`
        );
      } catch (notifError) {
        console.error("Error sending notification:", notifError);
      }
    }

    res.status(200).json({ message: "Participant removed successfully" });
  } catch (error) {
    console.error("Error removing participant:", error);
    res.status(500).json({
      message: "Error removing participant",
      error: error.message,
    });
  }
});

// Get event chat messages
app.get("/events/:eventId/messages", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, skip = 0, limit = 50 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if user is a participant
    if (userId) {
      const isParticipant = event.participants.some(
        (p) => p.userId.toString() === userId
      );
      if (!isParticipant) {
        return res.status(403).json({
          message: "Only participants can view event messages",
        });
      }
    }

    const messages = await EventMessage.find({ eventId })
      .populate("senderId", "name profileImages")
      .sort({ createdAt: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit));

    res.status(200).json({
      messages: messages.reverse(), // Return in chronological order
      count: messages.length,
    });
  } catch (error) {
    console.error("Error fetching event messages:", error);
    res.status(500).json({
      message: "Error fetching event messages",
      error: error.message,
    });
  }
});

// Get popular tags
app.get("/events/tags/popular", async (req, res) => {
  try {
    const tags = await Event.aggregate([
      { $match: { status: { $in: ["upcoming", "live", "full"] } } },
      { $unwind: "$tags" },
      { $group: { _id: "$tags", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 20 },
    ]);

    res.status(200).json({
      tags: tags.map((t) => ({ tag: t._id, count: t.count })),
    });
  } catch (error) {
    console.error("Error fetching popular tags:", error);
    res.status(500).json({
      message: "Error fetching popular tags",
      error: error.message,
    });
  }
});

// Admin endpoint to get all events
app.get("/admin/events", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      status,
      sortBy = "startTime",
      sortOrder = -1,
    } = req.query;

    const query = {};
    
    // Filter by status if provided
    if (status && status !== "all") {
      query.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOptions = {};
    sortOptions[sortBy] = parseInt(sortOrder);

    const events = await Event.find(query)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages")
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Event.countDocuments(query);

    res.status(200).json({
      events,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error fetching all events:", error);
    res.status(500).json({
      message: "Error fetching events",
      error: error.message,
    });
  }
});

// Get event by ID (MUST be after specific routes like /events/nearby, /events/search, etc.)
app.get("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    let event = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Update status if needed
    event = await updateEventStatus(event);

    res.status(200).json(event);
  } catch (error) {
    console.error("Error fetching event:", error);
    res.status(500).json({
      message: "Error fetching event",
      error: error.message,
    });
  }
});

// ============================================================
// NOTIFICATIONS ENDPOINTS
// ============================================================

// Get notifications for a user (paginated)
app.get("/notifications/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Notification.countDocuments({ userId });
    const unreadCount = await Notification.countDocuments({
      userId,
      read: false,
    });

    res.status(200).json({
      notifications,
      total,
      unreadCount,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({
      message: "Error fetching notifications",
      error: error.message,
    });
  }
});

// Mark a single notification as read
app.put("/notifications/:notificationId/read", async (req, res) => {
  try {
    const { notificationId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(notificationId)) {
      return res.status(400).json({ message: "Invalid notification ID format" });
    }

    const notification = await Notification.findByIdAndUpdate(
      notificationId,
      { read: true },
      { new: true }
    );

    if (!notification) {
      return res.status(404).json({ message: "Notification not found" });
    }

    res.status(200).json({
      message: "Notification marked as read",
      notification,
    });
  } catch (error) {
    console.error("Error marking notification as read:", error);
    res.status(500).json({
      message: "Error marking notification as read",
      error: error.message,
    });
  }
});

// Mark all notifications as read for a user
app.put("/notifications/:userId/read-all", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const result = await Notification.updateMany(
      { userId, read: false },
      { read: true }
    );

    res.status(200).json({
      message: `Marked ${result.modifiedCount} notifications as read`,
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error marking all notifications as read:", error);
    res.status(500).json({
      message: "Error marking notifications as read",
      error: error.message,
    });
  }
});

// Delete a notification
app.delete("/notifications/:notificationId", async (req, res) => {
  try {
    const { notificationId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(notificationId)) {
      return res.status(400).json({ message: "Invalid notification ID format" });
    }

    const notification = await Notification.findByIdAndDelete(notificationId);

    if (!notification) {
      return res.status(404).json({ message: "Notification not found" });
    }

    res.status(200).json({
      message: "Notification deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting notification:", error);
    res.status(500).json({
      message: "Error deleting notification",
      error: error.message,
    });
  }
});

// ============================================
// OPEN TAB - People Open to Activities
// ============================================

// Helper function to format active status
const formatActiveStatus = (lastActiveAt) => {
  if (!lastActiveAt) return "Active";
  
  const now = new Date();
  const lastActive = new Date(lastActiveAt);
  const diffMs = now - lastActive;
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const diffMonths = Math.floor(diffDays / 30);
  
  if (diffMins < 5) return "Active now";
  if (diffMins < 60) return `Active ${diffMins}m ago`;
  if (diffHours < 24) return `Active ${diffHours}h ago`;
  if (diffDays < 30) return `Active ${diffDays}d ago`;
  return `Active ${diffMonths}mo ago`;
};

// GET /users/nearby/open - Fetch nearby users who are open to activities
app.get("/users/nearby/open", async (req, res) => {
  try {
    const { 
      radius = 50000, 
      userId, 
      limit = 10, 
      skip = 0,
      search = ""
    } = req.query;

    // Require userId to get user's location from database
    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        message: "User ID is required",
      });
    }

    // Fetch user's location from database (IGNORE any client-sent lat/lng)
    const currentUser = await User.findById(userId).select("location blockedBy name");
    
    if (!currentUser) {
      console.log(`❌ [NEARBY/OPEN] User not found: ${userId}`);
      return res.status(404).json({
        message: "User not found",
      });
    }

    console.log(`👤 [NEARBY/OPEN] User: ${currentUser.name}, stored location: ${JSON.stringify(currentUser?.location?.coordinates)}`);

    // Check if user has valid location coordinates
    const userCoords = currentUser?.location?.coordinates;
    if (!userCoords || 
        !Array.isArray(userCoords) || 
        userCoords.length !== 2 || 
        (userCoords[0] === 0 && userCoords[1] === 0) ||
        !userCoords[0] || !userCoords[1]) {
      console.log(`❌ [NEARBY/OPEN] Invalid location for user ${currentUser.name}: ${JSON.stringify(userCoords)}`);
      return res.status(400).json({
        message: "User location not available. Please enable location services.",
        users: [],
        count: 0,
        hasMore: false,
      });
    }

    // MongoDB stores coordinates as [longitude, latitude]
    const lng = userCoords[0];
    const lat = userCoords[1];
    
    console.log(`📍 [NEARBY/OPEN] Using DB coordinates for ${currentUser.name}: lat=${lat}, lng=${lng}`);
    const maxDistance = parseInt(radius);
    const queryLimit = Math.min(parseInt(limit) || 10, 50); // Cap at 50
    const querySkip = parseInt(skip) || 0;
    const searchTerm = search.trim();

    console.log(`📍 [NEARBY/OPEN] Request: lat=${lat}, lng=${lng}, radius=${maxDistance}m, limit=${queryLimit}, skip=${querySkip}, search="${searchTerm}", userId=${userId}`);

    // Calculate date 90 days ago
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

    // Build exclusion list (always exclude self + blocked users)
    let excludeIds = [new mongoose.Types.ObjectId(userId)];
    if (currentUser?.blockedBy?.length > 0) {
      excludeIds = excludeIds.concat(currentUser.blockedBy);
    }

    // Build the query conditions
    const queryConditions = [
      // Only show users with showInOpenTab true (or not set, defaulting to true)
      {
        $or: [
          { showInOpenTab: { $exists: false } },
          { showInOpenTab: true }
        ]
      },
      // Must have been active in last 90 days
      {
        $or: [
          { lastActiveAt: { $gte: ninetyDaysAgo } },
          { updatedAt: { $gte: ninetyDaysAgo } } // Fallback for users without lastActiveAt
        ]
      },
      // Must have valid location
      { "location.coordinates": { $exists: true, $ne: [0, 0] } },
      // Must have at least one interest
      { interests: { $exists: true, $not: { $size: 0 } } },
      // Must have at least one profile image
      { profileImages: { $exists: true, $not: { $size: 0 } } },
      // Exclude self and blocked users
      ...(excludeIds.length > 0 ? [{ _id: { $nin: excludeIds } }] : []),
    ];

    // Add search filter if provided
    if (searchTerm) {
      queryConditions.push({
        name: { $regex: searchTerm, $options: "i" }
      });
    }

    const pipeline = [
      {
        $geoNear: {
          near: { type: "Point", coordinates: [lng, lat] },
          distanceField: "distance",
          maxDistance: maxDistance,
          spherical: true,
          query: { $and: queryConditions },
        },
      },
      {
        $project: {
          _id: 1,
          name: 1,
          profileImages: { $slice: ["$profileImages", 1] },
          interests: { $slice: ["$interests", 3] },
          distance: { $divide: ["$distance", 1000] }, // Convert to km
          lastActiveAt: 1,
          updatedAt: 1,
        },
      },
      // Sort by recency first (most recent first), then by distance
      {
        $addFields: {
          effectiveLastActive: {
            $ifNull: ["$lastActiveAt", "$updatedAt"]
          }
        }
      },
      { $sort: { effectiveLastActive: -1, distance: 1 } },
      { $skip: querySkip },
      { $limit: queryLimit + 1 }, // Fetch one extra to check if there's more
    ];

    const users = await User.aggregate(pipeline);

    // Check if there are more results
    const hasMore = users.length > queryLimit;
    if (hasMore) {
      users.pop(); // Remove the extra item
    }

    // Format the response
    const formattedUsers = users.map(user => ({
      _id: user._id,
      name: user.name,
      profileImages: user.profileImages,
      interests: user.interests,
      distance: Math.round(user.distance * 10) / 10, // Round to 1 decimal
      lastActiveAt: user.effectiveLastActive,
      activeStatus: formatActiveStatus(user.effectiveLastActive),
    }));

    console.log(`✅ [NEARBY/OPEN] Response: found ${formattedUsers.length} users, hasMore=${hasMore}`);
    if (formattedUsers.length > 0) {
      console.log(`   Users: ${formattedUsers.map(u => `${u.name} (${u.distance}km, ${u.activeStatus})`).join(", ")}`);
    }

    res.status(200).json({
      users: formattedUsers,
      count: formattedUsers.length,
      hasMore,
    });
  } catch (error) {
    console.error("❌ [NEARBY/OPEN] Error fetching open users:", error);
    res.status(500).json({
      message: "Error fetching open users",
      error: error.message,
    });
  }
});

// PUT /users/:userId/open-visibility - Update user's visibility in Open tab
app.put("/users/:userId/open-visibility", async (req, res) => {
  try {
    const { userId } = req.params;
    const { showInOpenTab } = req.body;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    if (typeof showInOpenTab !== "boolean") {
      return res.status(400).json({ message: "showInOpenTab must be a boolean" });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { showInOpenTab },
      { new: true }
    ).select("showInOpenTab");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: `Visibility ${showInOpenTab ? "enabled" : "disabled"}`,
      showInOpenTab: user.showInOpenTab,
    });
  } catch (error) {
    console.error("Error updating open visibility:", error);
    res.status(500).json({
      message: "Error updating visibility",
      error: error.message,
    });
  }
});

// GET /users/:userId/debug-location - Debug endpoint to check user's stored location
app.get("/users/:userId/debug-location", async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const user = await User.findById(userId).select("name location updatedAt");
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const coords = user?.location?.coordinates;
    const lng = coords?.[0];
    const lat = coords?.[1];

    // Check if coords look like San Francisco (for debugging)
    const isSanFrancisco = lat && lng && 
      Math.abs(lat - 37.7749) < 0.5 && 
      Math.abs(lng - (-122.4194)) < 0.5;

    res.status(200).json({
      userId,
      name: user.name,
      location: user.location,
      coordinates: { latitude: lat, longitude: lng },
      isSanFrancisco,
      lastUpdated: user.updatedAt,
      message: isSanFrancisco 
        ? "⚠️ Location appears to be San Francisco - may need to update from real device" 
        : "✅ Location looks valid",
    });
  } catch (error) {
    console.error("Error checking user location:", error);
    res.status(500).json({ message: "Error checking location", error: error.message });
  }
});

// POST /events/:eventId/respond-suggestion - Accept or decline an activity suggestion
app.post("/events/:eventId/respond-suggestion", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, response } = req.body; // response: "accept" or "decline"

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Valid user ID is required" });
    }

    if (!["accept", "decline"].includes(response)) {
      return res.status(400).json({ message: "Response must be 'accept' or 'decline'" });
    }

    // Find the event
    const event = await Event.findById(eventId).populate("hostId", "name profileImages pushToken");

    if (!event) {
      return res.status(404).json({ message: "Activity not found" });
    }

    // Verify the event is a suggestion and this user is a recipient
    if (event.status !== "suggested") {
      return res.status(400).json({ message: "This activity is not a suggestion" });
    }

    // Check if user is authorized (single suggestion or group invite)
    const isSingleRecipient = event.suggestedToUserId?.toString() === userId;
    const isGroupRecipient = event.suggestedToUserIds?.some(id => id.toString() === userId);
    
    if (!isSingleRecipient && !isGroupRecipient) {
      return res.status(403).json({ message: "You are not authorized to respond to this suggestion" });
    }

    const isGroupInvite = event.suggestedToUserIds && event.suggestedToUserIds.length > 0;

    // Check if suggestion has expired
    if (event.expiresAt && new Date(event.expiresAt) < new Date()) {
      await Event.findByIdAndUpdate(eventId, { status: "cancelled" });
      return res.status(400).json({ message: "This suggestion has expired" });
    }

    if (response === "accept") {
      // Check if user already joined (prevent duplicate joins for group invites)
      const alreadyJoined = event.participants.some(p => p.userId?.toString() === userId);
      if (alreadyJoined) {
        return res.status(400).json({ message: "You have already accepted this activity" });
      }

      // Build the update
      const participantsToAdd = [];
      
      // For first acceptance, add the host as participant too
      const isFirstAcceptance = event.participants.length === 0;
      if (isFirstAcceptance) {
        participantsToAdd.push({
          userId: event.hostId._id,
          status: "going",
          joinedAt: new Date(),
        });
      }
      
      // Add the responding user
      participantsToAdd.push({
        userId: userId,
        status: "going",
        joinedAt: new Date(),
      });

      await Event.findByIdAndUpdate(eventId, {
        status: "upcoming",
        $push: {
          participants: { $each: participantsToAdd },
        },
      });

      // Notify the suggester that their suggestion was accepted
      const respondingUser = await User.findById(userId).select("name profileImages");
      
      await createNotification({
        userId: event.hostId._id,
        type: "suggestion_accepted",
        title: "Suggestion Accepted!",
        message: isGroupInvite 
          ? `${respondingUser.name} joined your group activity: ${event.title}`
          : `${respondingUser.name} accepted your activity suggestion: ${event.title}`,
        eventId: event._id,
        eventName: event.title,
        actorId: userId,
        actorName: respondingUser.name,
        actorImage: respondingUser.profileImages?.[0],
      });

      res.status(200).json({
        message: "Suggestion accepted! Activity is now live.",
        event: await Event.findById(eventId).populate("hostId", "name profileImages"),
      });
    } else {
      // Decline: For group invites, just remove this user from the invite list
      // For single invites, cancel the event
      if (isGroupInvite) {
        // Remove user from suggestedToUserIds
        await Event.findByIdAndUpdate(eventId, {
          $pull: { suggestedToUserIds: new mongoose.Types.ObjectId(userId) },
        });
        
        // Check if all users have declined (no one left in the list)
        const updatedEvent = await Event.findById(eventId);
        if (updatedEvent.suggestedToUserIds.length === 0 && updatedEvent.participants.length === 0) {
          // No one accepted and everyone declined - cancel the event
          await Event.findByIdAndUpdate(eventId, { status: "cancelled" });
        }
        
        res.status(200).json({
          message: "Invitation declined",
        });
      } else {
        // Single invite - cancel the event
        await Event.findByIdAndUpdate(eventId, { status: "cancelled" });

        res.status(200).json({
          message: "Suggestion declined",
        });
      }
    }
  } catch (error) {
    console.error("Error responding to suggestion:", error);
    res.status(500).json({
      message: "Error responding to suggestion",
      error: error.message,
    });
  }
});

// PUT /users/:userId/last-active - Update user's last active timestamp
app.put("/users/:userId/last-active", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    await User.findByIdAndUpdate(userId, { lastActiveAt: new Date() });

    res.status(200).json({ message: "Last active updated" });
  } catch (error) {
    console.error("Error updating last active:", error);
    res.status(500).json({
      message: "Error updating last active",
      error: error.message,
    });
  }
});
