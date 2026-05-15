const express = require("express");
const { getTicketForUser, scanTicket } = require("../services/ticketService");

const router = express.Router();

router.get("/events/:eventId/tickets/me", async (req, res) => {
  try {
    const { eventId } = req.params;
    const userId = req.query.userId;
    if (!userId) {
      return res.status(400).json({ message: "userId is required" });
    }
    const ticket = await getTicketForUser({ eventId, userId });
    return res.status(200).json({ ticket });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to fetch ticket",
      ...(error.payload || {}),
    });
  }
});

router.post("/events/:eventId/tickets/scan", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { ticketCode, scannerUserId } = req.body;
    if (!scannerUserId) {
      return res.status(400).json({ message: "scannerUserId is required" });
    }
    const result = await scanTicket({ eventId, ticketCode, scannerUserId });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to scan ticket",
      ...(error.payload || {}),
    });
  }
});

module.exports = router;
