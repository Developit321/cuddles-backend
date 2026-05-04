const EventPayment = require("../models/EventPayment");
const Event = require("../models/Event");

/**
 * Seats that block capacity: for paid events, include `interested` (payment-hold / checkout).
 * For free events, only committed attendees count.
 */
function countOccupiedSeats(event) {
  const participants = event.participants || [];
  if (event.isPaid) {
    return participants.filter(
      (p) => p && p.status && ["going", "checked_in", "interested"].includes(p.status)
    ).length;
  }
  return participants.filter((p) => p && (p.status === "going" || p.status === "checked_in")).length;
}

/** Pure status transition logic (mirrors previous updateEventStatus behavior). */
function computeNextEventStatus(event) {
  const now = new Date();
  let newStatus = event.status;

  if (event.status === "cancelled" || event.status === "ended") {
    return event.status;
  }

  const startTime =
    event.startTime instanceof Date ? event.startTime : new Date(event.startTime);
  const endTime = event.endTime
    ? event.endTime instanceof Date
      ? event.endTime
      : new Date(event.endTime)
    : null;
  const capacity = event.capacity != null ? event.capacity : 6;

  if (startTime <= now && event.status === "upcoming") {
    newStatus = "live";
  }

  if (endTime && endTime <= now) {
    newStatus = "ended";
  }

  const fourHoursAfterStart = new Date(startTime.getTime() + 4 * 60 * 60 * 1000);
  if (now >= fourHoursAfterStart && newStatus !== "ended") {
    newStatus = "ended";
  }

  const occupiedCount = countOccupiedSeats(event);
  if (occupiedCount >= capacity && newStatus !== "ended") {
    newStatus = "full";
  } else if (occupiedCount < capacity && event.status === "full") {
    newStatus = startTime <= now ? "live" : "upcoming";
  }

  return newStatus;
}

/**
 * Remove expired payment-hold participants (interested + pending_payment checkout expired).
 * Always loads by id (never save a populated Event — Mongoose will 500 on embedded refs).
 */
async function expirePendingPaidAdmissions(eventId) {
  const id = eventId && (eventId._id || eventId);
  if (!id) return { removedCount: 0 };

  const event = await Event.findById(id);
  if (!event?.isPaid || !Array.isArray(event.participants)) {
    return { removedCount: 0 };
  }

  const now = new Date();
  const pendingParticipantIds = event.participants
    .filter((p) => p?.status === "interested")
    .map((p) => p.userId?.toString())
    .filter(Boolean);

  if (!pendingParticipantIds.length) {
    return { removedCount: 0 };
  }

  const expiredPayments = await EventPayment.find({
    eventId: event._id,
    userId: { $in: pendingParticipantIds },
    admissionStatus: "pending_payment",
    expiresAt: { $ne: null, $lte: now },
  }).select("_id userId");

  if (!expiredPayments.length) {
    return { removedCount: 0 };
  }

  const expiredUserIds = new Set(expiredPayments.map((p) => p.userId.toString()));
  event.participants = event.participants.filter(
    (p) => !expiredUserIds.has(p.userId?.toString())
  );

  await EventPayment.updateMany(
    {
      _id: { $in: expiredPayments.map((p) => p._id) },
      admissionStatus: "pending_payment",
    },
    {
      $set: {
        status: "expired",
        admissionStatus: "expired",
      },
    }
  );

  event.status = computeNextEventStatus(event);
  await event.save();

  return { removedCount: expiredUserIds.size };
}

/**
 * After a real provider checkout is created (or reused), ensure open paid events
 * have an `interested` participant row until payment completes or the hold expires.
 * No-op if the user is already on the participant list.
 */
async function attachOpenPaidCheckoutSeatHold({ eventId, userId }) {
  await expirePendingPaidAdmissions(eventId);
  const event = await Event.findById(eventId);
  if (!event || !event.isPaid || event.requiresApproval) {
    return { attached: false, alreadyPresent: false };
  }

  const capacity = event.capacity != null ? event.capacity : 6;
  const uid = userId.toString();
  const exists = event.participants.some((p) => {
    const raw = p.userId?._id || p.userId;
    return raw && raw.toString() === uid;
  });
  if (exists) {
    return { attached: false, alreadyPresent: true };
  }

  if (countOccupiedSeats(event) >= capacity) {
    const err = new Error("Event is full");
    err.status = 409;
    throw err;
  }

  event.participants.push({
    userId,
    status: "interested",
    joinedAt: new Date(),
  });
  event.status = computeNextEventStatus(event);
  await event.save();
  return { attached: true, alreadyPresent: false };
}

/** Drop `interested` checkout/payment-hold row when payment fails, expires, or user abandons. */
async function removeInterestedHoldForPayment(payment) {
  if (!payment?.eventId || !payment?.userId) return;
  const event = await Event.findById(payment.eventId);
  if (!event || !event.isPaid || !Array.isArray(event.participants)) return;
  const uid = payment.userId.toString();
  const nextParticipants = event.participants.filter(
    (p) => !(p.userId?.toString() === uid && p.status === "interested")
  );
  if (nextParticipants.length === event.participants.length) return;
  event.participants = nextParticipants;
  event.status = computeNextEventStatus(event);
  await event.save();
}

module.exports = {
  countOccupiedSeats,
  computeNextEventStatus,
  expirePendingPaidAdmissions,
  attachOpenPaidCheckoutSeatHold,
  removeInterestedHoldForPayment,
};
