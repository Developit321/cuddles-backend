const express = require("express");
const {
  checkIfAnsweredToday,
  updateUserCountry,
  updateAllUsersCountries,
  updateUsersWithNoCountry,
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

// Update countries for users with coordinates but no country
router.post("/update-missing-countries", async (req, res) => {
  try {
    console.log("🚀 Starting update for users with missing countries...");
    const results = await updateUsersWithNoCountry();
    res.status(200).json({
      success: true,
      ...results,
    });
  } catch (error) {
    console.error("❌ Error in update-missing-countries endpoint:", error);
    res.status(500).json({
      success: false,
      message: error.message,
      details: error.stack,
    });
  }
});

module.exports = router;
