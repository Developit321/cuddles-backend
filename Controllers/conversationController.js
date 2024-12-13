const User = require("../models/User");

const getUnreadCounts = async (req, res) => {
  try {
    const { userId } = req.params;

    // Fetch user data including conversations and receivedLikes
    const response = await User.findById(userId)
      .select("conversations receivedLikes")
      .populate("receivedLikes", "_id"); // Optional if you need user details for likes

    if (!response) {
      return res.status(404).json({ message: "User not found" });
    }

    // Ensure conversations and receivedLikes are arrays, if not, default to empty arrays
    const conversations = response.conversations || [];
    const receivedLikes = response.receivedLikes || [];

    // Map unread counts
    const unreadCounts = conversations.map((conversation) => ({
      receiverId: conversation.receiverId,
      unreadMessagesCount: conversation.unreadMessagesCount,
    }));

    // Get the count of received likes
    const receivedLikesCount = receivedLikes.length;

    res.status(200).json({ unreadCounts, receivedLikesCount });
  } catch (error) {
    console.error("Error fetching unread counts and likes:", error); // Log the error
    res.status(500).json({ message: "Error fetching data", error });
  }
};

module.exports = { getUnreadCounts };
