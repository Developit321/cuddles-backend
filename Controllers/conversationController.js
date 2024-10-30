const user = require("../models/User");

const getUnreadCounts = async (req, res) => {
  try {
    const { userId } = req.params;

    // Find the user's conversations with unread message counts
    const response = await user.findById(userId).select("conversations");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const unreadCounts = response.conversations.map((conversation) => ({
      receiverId: conversation.receiverId,
      unreadMessagesCount: conversation.unreadMessagesCount,
    }));

    res.status(200).json({ unreadCounts });
  } catch (error) {
    res.status(500).json({ message: "Error fetching unread counts", error });
  }
};

module.exports = { getUnreadCounts };
