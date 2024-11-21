const express = require("express");
const { checkIfAnsweredToday } = require("../Controllers/userController"); // Use require for importing

const router = express.Router();

router.get("/check-answered/:userId", async (req, res) => {
  const { userId } = req.params;
  const answeredToday = await checkIfAnsweredToday(userId);
  if (answeredToday) {
    return res
      .status(200)
      .json({ message: "User has answered today's question." });
  } else {
    return res
      .status(400)
      .json({ message: "User has not answered today's question." });
  }
});

// API route to test cron job
router.get("/test-cron", async (req, res) => {
  try {
    await sendDailyReminders(); // Manually trigger the cron job function
    res
      .status(200)
      .json({ message: "Daily reminders triggered successfully!" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error triggering daily reminders", error });
  }
});

module.exports = router;

module.exports = router;
