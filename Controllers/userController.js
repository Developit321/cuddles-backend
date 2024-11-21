const User = require("../models/User"); // Use require to import User model

const checkIfAnsweredToday = async (userId) => {
  const now = new Date();
  const startOfDay = new Date(now.setHours(0, 0, 0, 0));
  const endOfDay = new Date(now.setHours(23, 59, 59, 999));

  try {
    const user = await User.findById(userId); // Use User model to find the user by ID
    if (!user) {
      return false;
    }

    const answeredToday =
      user.dailyQuestion.answeredAt >= startOfDay &&
      user.dailyQuestion.answeredAt <= endOfDay;

    console.log(answeredToday);
    return answeredToday;
  } catch (error) {
    console.error("Error checking if user answered today:", error);
    return false;
  }
};

module.exports = { checkIfAnsweredToday }; // Export the function using CommonJS
