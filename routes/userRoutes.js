const express = require("express");
const {
  checkIfAnsweredToday,
  updateUserCountry,
  updateAllUsersCountries,
} = require("../Controllers/userController");

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

// Update country for a single user
router.post("/update-country/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await updateUserCountry(userId);
    res.status(200).json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
});

// Update countries for all users with coordinates
router.post("/update-all-countries", async (req, res) => {
  try {
    const results = await updateAllUsersCountries();
    res.status(200).json({
      success: true,
      ...results,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
});

// API route to test cron job
router.get("/test-cron", async (req, res) => {
  try {
    await sendDailyReminders();
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
