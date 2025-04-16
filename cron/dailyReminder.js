const cron = require("node-cron"); // Use require for node-cron
const { sendNotification } = require("../notifications/pushNotifications"); // Use require to import sendNotification function
const User = require("../models/User"); // Use require to import User model
const { checkIfAnsweredToday } = require("../Controllers/userController"); // Use require for checkIfAnsweredToday

// Function to send daily reminders to users who haven't answered today's question
const sendDailyReminders = async () => {
  try {
    const users = await User.find({ pushToken: { $exists: true } });

    for (const user of users) {
      const answeredToday = await checkIfAnsweredToday(user._id);
      if (!answeredToday) {
        await sendNotification(
          user.pushToken,
          "Reminder: Answer Today's Question!",
          "You haven't gotten to it yet—take a moment to share your thoughts!"
        );
      }
    }

    console.log("Daily Riminder Sent");
  } catch (error) {
    console.error("Error sending daily reminders:", error);
  }
};

// The cron schedule has been removed as requested

module.exports = { sendDailyReminders };
