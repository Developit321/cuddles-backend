const crypto = require("crypto");
const mongoose = require("mongoose");
const Event = require("../models/Event");
const EventPayment = require("../models/EventPayment");
const User = require("../models/User");
const Notification = require("../models/Notification");
const notificationStrings = require("../notifications/notificationStrings");
const { sendNotification } = require("../notifications/pushNotifications");

const getStrings = (lang) =>
  notificationStrings[lang] || notificationStrings.en;

const interpolate = (str, params = {}) =>
  Object.entries(params).reduce(
    (s, [k, v]) => s.replace(new RegExp(`\\{${k}\\}`, "g"), v),
    str
  );

const isValidExpoPushToken = (token) =>
  typeof token === "string" &&
  (token.startsWith("ExponentPushToken[") || token.startsWith("ExpoPushToken["));

const generateTicketCode = () => {
  const raw = crypto.randomBytes(8).toString("hex").toUpperCase();
  return `INV-${raw}`;
};

const issueTicketForPayment = async (payment) => {
  if (!payment?._id) return null;
  if (payment.status !== "paid" || payment.admissionStatus !== "admitted") {
    return null;
  }
  if (payment.ticketStatus === "active" || payment.ticketStatus === "scanned") {
    return payment;
  }
  if (payment.ticketStatus === "void") {
    return null;
  }

  let ticketCode = payment.ticketCode;
  if (!ticketCode) {
    ticketCode = generateTicketCode();
  }

  const updated = await EventPayment.findByIdAndUpdate(
    payment._id,
    {
      $set: {
        ticketCode,
        ticketStatus: "active",
        ticketIssuedAt: payment.ticketIssuedAt || new Date(),
      },
    },
    { new: true }
  );
  return updated;
};

const voidTicketForPayment = async (payment) => {
  if (!payment?._id) return;
  payment.ticketStatus = "void";
  payment.ticketCode = payment.ticketCode || "";
  await payment.save();
};

const formatTicketResponse = (payment, event, attendee, host) => {
  const start = event.startTime ? new Date(event.startTime) : null;
  const location = event.location || {};
  const addressParts = [location.name, location.address].filter(Boolean);

  return {
    ticketCode: payment.ticketCode,
    ticketStatus: payment.ticketStatus,
    orderId: payment.ticketCode,
    ticketType: "General admission",
    event: {
      id: event._id,
      title: event.title,
      coverImage: event.coverImage || null,
      startTime: event.startTime,
      currency: event.currency || "ZAR",
      priceAmount: event.priceAmount || 0,
    },
    host: {
      id: host?._id,
      name: host?.name || "Host",
    },
    attendee: {
      id: attendee?._id,
      name: attendee?.name || "Guest",
    },
    dateLabel: start
      ? start.toLocaleDateString("en-GB", {
          day: "2-digit",
          month: "2-digit",
          year: "numeric",
        })
      : "TBD",
    timeLabel: start
      ? start.toLocaleTimeString("en-US", {
          hour: "numeric",
          minute: "2-digit",
          hour12: true,
        })
      : "TBD",
    placeLabel: addressParts.join(", ") || "Location TBD",
    scannedAt: payment.ticketScannedAt,
  };
};

const getTicketForUser = async ({ eventId, userId }) => {
  if (!mongoose.Types.ObjectId.isValid(eventId) || !mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid ID format");
    err.status = 400;
    throw err;
  }

  let payment = await EventPayment.findOne({
    eventId,
    userId,
    status: "paid",
    admissionStatus: "admitted",
  }).sort({ paidAt: -1, createdAt: -1 });

  if (!payment) {
    const err = new Error("No valid ticket found for this event");
    err.status = 404;
    throw err;
  }

  if (!payment.ticketCode || payment.ticketStatus === "none") {
    payment = await issueTicketForPayment(payment);
  }

  if (!payment || payment.ticketStatus === "void") {
    const err = new Error("Ticket is no longer valid");
    err.status = 410;
    throw err;
  }

  if (!["active", "scanned"].includes(payment.ticketStatus)) {
    const err = new Error("Ticket is not available");
    err.status = 404;
    throw err;
  }

  const event = await Event.findById(eventId).lean();
  if (!event) {
    const err = new Error("Event not found");
    err.status = 404;
    throw err;
  }

  const [attendee, host] = await Promise.all([
    User.findById(userId).select("name profileImages").lean(),
    User.findById(event.hostId).select("name profileImages").lean(),
  ]);

  return formatTicketResponse(payment, event, attendee, host);
};

const notifyCheckIn = async ({ event, userId, checkedInUser }) => {
  const otherParticipantIds = (event.participants || [])
    .filter((p) => p.userId && p.userId.toString() !== userId.toString())
    .map((p) => p.userId);

  if (!otherParticipantIds.length) return;

  const otherParticipants = await User.find({
    _id: { $in: otherParticipantIds },
  }).select("_id preferredLanguage pushToken");

  for (const participant of otherParticipants) {
    try {
      const ciStr =
        getStrings(participant.preferredLanguage).eventCheckin ||
        getStrings("en").eventCheckin;
      const title = interpolate(ciStr.title, {
        name: checkedInUser.name,
        eventTitle: event.title,
      });
      const message = interpolate(ciStr.body, {
        name: checkedInUser.name,
        eventTitle: event.title,
      });

      const notification = new Notification({
        userId: participant._id,
        type: "event_checkin",
        title,
        message,
        eventId: event._id,
        eventName: event.title,
        actorId: userId,
        actorName: checkedInUser.name,
        category: "transactional",
      });
      await notification.save();

      const token = participant.pushToken;
      if (isValidExpoPushToken(token)) {
        await sendNotification(token, title, message, {
          type: "event_checkin",
          eventId: event._id.toString(),
          actorId: userId.toString(),
        });
      }
    } catch (notifError) {
      console.error("[TicketScan] Error sending check-in notification:", notifError);
    }
  }
};

const markParticipantCheckedIn = async (event, userId) => {
  const participantIndex = event.participants.findIndex(
    (p) => p?.userId && p.userId.toString() === userId.toString()
  );
  if (participantIndex === -1) {
    return false;
  }
  event.participants[participantIndex].status = "checked_in";
  await event.save();

  const otherCheckedIn = event.participants.filter(
    (p) =>
      p.status === "checked_in" && p.userId && p.userId.toString() !== userId.toString()
  );
  for (const peer of otherCheckedIn) {
    const peerId = peer.userId._id || peer.userId;
    try {
      await User.findByIdAndUpdate(userId, {
        $addToSet: { coAttendees: peerId },
      });
      await User.findByIdAndUpdate(peerId, {
        $addToSet: { coAttendees: userId },
      });
    } catch (coErr) {
      console.error("[TicketScan] Error updating coAttendees:", coErr);
    }
  }
  return true;
};

const scanTicket = async ({ eventId, ticketCode, scannerUserId }) => {
  if (
    !mongoose.Types.ObjectId.isValid(eventId) ||
    !mongoose.Types.ObjectId.isValid(scannerUserId)
  ) {
    const err = new Error("Invalid ID format");
    err.status = 400;
    throw err;
  }

  const normalizedCode = String(ticketCode || "").trim().toUpperCase();
  if (!normalizedCode) {
    const err = new Error("Ticket code is required");
    err.status = 400;
    throw err;
  }

  const event = await Event.findById(eventId);
  if (!event) {
    const err = new Error("Event not found");
    err.status = 404;
    throw err;
  }

  if (event.hostId.toString() !== scannerUserId.toString()) {
    const err = new Error("Only the host can scan tickets for this event");
    err.status = 403;
    throw err;
  }

  const payment = await EventPayment.findOne({
    eventId: event._id,
    ticketCode: normalizedCode,
  });

  if (!payment) {
    const err = new Error("Ticket not found for this event");
    err.status = 404;
    throw err;
  }

  const attendee = await User.findById(payment.userId).select("name profileImages").lean();
  const attendeeName = attendee?.name || "Guest";

  if (payment.status === "refunded" || payment.ticketStatus === "void") {
    const err = new Error("This ticket has been voided");
    err.status = 410;
    throw err;
  }

  if (payment.status !== "paid" || payment.admissionStatus !== "admitted") {
    const err = new Error("This ticket is not valid for entry");
    err.status = 400;
    throw err;
  }

  if (payment.ticketStatus === "scanned") {
    const err = new Error("Ticket already scanned");
    err.status = 409;
    err.payload = {
      success: false,
      alreadyScanned: true,
      attendeeName,
      scannedAt: payment.ticketScannedAt,
    };
    throw err;
  }

  payment.ticketStatus = "scanned";
  payment.ticketScannedAt = new Date();
  payment.ticketScannedBy = scannerUserId;
  await payment.save();

  await markParticipantCheckedIn(event, payment.userId);

  const checkedInUser = attendee || { name: attendeeName };
  await notifyCheckIn({
    event,
    userId: payment.userId,
    checkedInUser,
  });

  return {
    success: true,
    alreadyScanned: false,
    attendeeName,
    attendeeId: payment.userId,
    scannedAt: payment.ticketScannedAt,
  };
};

module.exports = {
  issueTicketForPayment,
  voidTicketForPayment,
  getTicketForUser,
  scanTicket,
};
