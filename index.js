const bodyParser = require("body-parser");
const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");
const User = require("./models/User");
const Message = require("./models/message");
const jwt = require("jsonwebtoken");
const cloudinary = require("cloudinary");
const app = express();
const port = 3000;
const multer = require("multer");
const { resolve } = require("path");
const http = require("http").createServer(app);
const io = require("socket.io")(http); // Pass the HTTP server instance

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

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
  .then(() => {
    console.log("Connected to the Database");
  })
  .catch((error) => {
    console.log("Error connecting to the Database", error);
  });

http.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// Socket.io connection
io.on("connection", (socket) => {
  console.log("A user connected: " + socket.id);

  // Listen for the join event and make the user join a specific room
  socket.on("join", ({ userId }) => {
    socket.join(userId); // User joins a room with their own userId
    console.log("User joined room:", userId);
  });

  // Listen for incoming messages
  socket.on("sendMessage", async ({ senderId, receiverId, message }) => {
    try {
      console.log("Message received from client:", {
        senderId,
        receiverId,
        message,
      });

      const newMessage = new Message({ senderId, receiverId, message });
      await newMessage.save();

      // Emit the message to the receiver's room
      io.to(receiverId).emit("receiveMessage", newMessage); // Emit to the room based on receiverId
    } catch (error) {
      console.error("Error saving message:", error);
    }
  });

  // Handle user disconnect
  socket.on("disconnect", () => {
    console.log("A user disconnected: " + socket.id);
  });
});

// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, age, location } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const newUser = new User({
      name,
      email,
      password,
      age,
      location,
    });

    // Verification
    newUser.VerificationToken = crypto.randomBytes(20).toString("hex");

    // Save the user
    await newUser.save();

    // Send verification email
    sendVerificationEmail(newUser.email, newUser.VerificationToken);

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log("Error registering the user", error);
    res.status(500).json({ message: "Registration failed" });
  }
});

// Send verification email
const sendVerificationEmail = async (email, VerificationToken) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "makofanethulane53@gmail.com", // Use environment variables
      pass: "qlrm olky tyzb usur",
    },
  });

  const mailOptions = {
    from: "cuddles.com",
    to: email,
    subject: "Email verification",
    text: `Click on this link to verify your email: http://192.168.0.112:3000/verify/${VerificationToken}`,
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

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "invalid email or password" });
    }

    if (user.password !== password) {
      return res.status(401).json({ message: "invalid password" });
    }

    const token = jwt.sign({ userId: user._id }, secretKey);

    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: "login fialed" });
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

app.put("/users/:userId/interests/remove", async (req, res) => {
  try {
    const { userId } = req.params;
    const { interests } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { interests: { $each: interests } } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res
      .status(200)
      .json({ message: "user interestts removed Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "error removing the users interests" });
  }
});

//looking for endpoint

app.put("/users/:userId/lookingfor/add", async (req, res) => {
  try {
    const { userId } = req.params;
    const { lookingFor } = req.body;

    if (
      !Array.isArray(lookingFor) ||
      lookingFor.some((item) => typeof item !== "string")
    ) {
      return res.status(400).json({ message: "Invalid lookingFor data" });
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
      .json({ message: "User looking for updated successfully" });
  } catch (error) {
    console.error("Error updating looking for:", error);
    return res
      .status(500)
      .json({ message: "Error updating the user's looking for" });
  }
});

// remove looking for
app.put("/users/:userId/lookingFor/remove", async (req, res) => {
  try {
    const { userId } = req.params;
    const { lookingFor } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { interests: lookingFor } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res
      .status(200)
      .json({ message: "user LookingFor removed Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "error removing the users LookingFor" });
  }
});

//get users data

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

    if (imageUrl) {
      // Update user profile with Cloudinary URL
      console.log(imageUrl);
      const user = await User.findByIdAndUpdate(
        userId,
        { $addToSet: { profileImages: imageUrl } },
        { new: true }
      );
    }

    if (!userId) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({ message: "upload was a success" });
  } catch (error) {
    console.error("File upload failed: ", error);
    res.status(500).json({ error: "File upload failed" });
  }
});
// endpoint to fetch users

app.get("/profiles", async (req, res) => {
  try {
    const { userId, gender } = req.query;

    console.log(gender);

    if (!userId || !gender) {
      return res
        .status(400)
        .json({ message: "userId and gender are required" });
    }

    let filter = { gender: gender === "male" ? "female" : "male" };

    const currentUser = await User.findById(userId)
      .populate("Matches", "_id")
      .populate("crushes", "_id");

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Ensure `matches` and `crushes` are arrays
    const friendsIds = (currentUser.Matches || []).map((friend) => friend._id);
    const crushesId = (currentUser.crushes || []).map((crush) => crush._id);

    const profiles = await User.find(filter)
      .where("_id")
      .nin([userId, ...friendsIds, ...crushesId]);

    return res.status(200).json({ profiles });
  } catch (error) {
    console.error("Error fetching user profiles:", error);
    res.status(500).json({ message: "Error fetching user profiles" });
  }
});

//send a like
app.post("/likeprofile", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Update the recipient's likes
    await User.findByIdAndUpdate(selectedUserId, {
      $push: { recievedLikes: currentUserId },
    });

    // Update the current user's crushes
    await User.findByIdAndUpdate(currentUserId, {
      $push: { crushes: selectedUserId },
    });

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
    const recievedLikesArray = [];
    const { userId } = req.params;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }

    for (const likedUserId of user.recievedLikes) {
      const likedUser = await User.findById(likedUserId);

      if (likedUser) {
        recievedLikesArray.push(likedUser);
      }
    }
    res.status(200).json(recievedLikesArray);
  } catch (error) {
    res
      .status(500)
      .json({ message: "failed to retrieve the recieved likes userId" });
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

    res.sendStatus(200);
  } catch (error) {
    res.status(500).json({ message: "failed to match the users", error });
  }
});

// fetch the users you matched with

app.get("/matches/:userId/info", async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }

    const matchIds = user.Matches;
    const matches = await User.find({ _id: { $in: matchIds } });

    res.status(200).json(matches);
  } catch (error) {
    res
      .status(500)
      .json({ message: "failed to retrieve the recieved likes userId" });
  }
});

app.delete("/users/:userId/images", async (req, res) => {
  const { userId } = req.params;
  const { imageUrl } = req.body;

  if (!imageUrl) {
    return res.status(400).json({ error: "Image URL is required" });
  }

  try {
    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { profileImages: imageUrl } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res
      .status(200)
      .json({ message: "Image deleted successfully", user });
  } catch (error) {
    console.error("Error deleting image:", error);
    return res.status(500).json({ error: "Failed to delete image" });
  }
});
app.get("/messages/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const messages = await Message.find({
      $or: [{ sender: userId }, { receiver: userId }],
    }).populate("sender receiver"); // Assuming you want to populate user data
    res.status(200).json(messages);
  } catch (error) {
    res.status(500).json({ message: "Failed to retrieve messages", error });
  }
});
