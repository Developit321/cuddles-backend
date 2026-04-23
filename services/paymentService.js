const crypto = require("crypto");
const mongoose = require("mongoose");
const Event = require("../models/Event");
const User = require("../models/User");
const EventPayment = require("../models/EventPayment");
const FeePolicy = require("../models/FeePolicy");
const HostPayoutProfile = require("../models/HostPayoutProfile");
const HostPayoutLedger = require("../models/HostPayoutLedger");
const { getActiveProviderName, getPaymentProvider } = require("../payments/providerRegistry");
const { attachOpenPaidCheckoutSeatHold, removeInterestedHoldForPayment } = require("./eventSeatHold");

const HOST_PAYOUT_STATUSES = new Set([
  "not_applied",
  "pending_review",
  "action_required",
  "active",
  "rejected",
  "suspended",
]);

function normalizeHostPayoutStatus(value) {
  const raw = (value == null ? "" : String(value)).trim().toLowerCase();
  if (HOST_PAYOUT_STATUSES.has(raw)) return raw;
  return "not_applied";
}

const QUOTE_TTL_MS = 10 * 60 * 1000;
const quoteStore = new Map();
const ACTIVE_CHECKOUT_STATUSES = new Set(["initialized", "pending"]);
const SUCCESS_STATES = new Set(["paid", "success", "completed"]);

const toMoney = (value) => Math.max(0, Math.round(Number(value) || 0));
const LEDGER_STATUSES = new Set(["accrued", "on_hold", "eligible", "paid_out", "reversed"]);
const LEDGER_SORT_FIELDS = new Set([
  "createdAt",
  "updatedAt",
  "hostOwedAmount",
  "grossAmount",
  "paidOutAt",
  "eligibleAt",
]);

const normalizeLedgerStatus = (value) => {
  const raw = String(value || "").trim().toLowerCase();
  return LEDGER_STATUSES.has(raw) ? raw : "";
};

const normalizeSortOrder = (value) => (Number(value) === 1 ? 1 : -1);

const normalizeDateInput = (value, { endOfDay = false } = {}) => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  if (endOfDay) {
    date.setHours(23, 59, 59, 999);
  } else {
    date.setHours(0, 0, 0, 0);
  }
  return date;
};

const buildLedgerAmountsFromPayment = (payment) => {
  const grossAmount = toMoney(payment.amount);
  const platformCommissionAmount = toMoney(payment.appFeeAmount);
  const providerFeeAmount = toMoney(payment.processingFeeAmount);
  const taxAmount = toMoney(payment.taxAmount);
  const hostOwedAmount = Math.max(0, grossAmount - platformCommissionAmount - providerFeeAmount - taxAmount);
  return {
    grossAmount,
    platformCommissionAmount,
    providerFeeAmount,
    taxAmount,
    hostOwedAmount,
  };
};

const upsertLedgerForPayment = async (payment, options = {}) => {
  if (!payment || String(payment.status) !== "paid") return null;
  const amounts = buildLedgerAmountsFromPayment(payment);
  const holdStatus = options.holdStatus || "on_hold";
  const baseSet = {
    eventId: payment.eventId,
    paymentId: payment._id,
    hostId: payment.hostId,
    payerUserId: payment.userId,
    provider: payment.provider,
    providerReference: payment.providerReference || "",
    currency: String(payment.currency || "ZAR").toUpperCase(),
    ...amounts,
    status: holdStatus,
    accruedAt: payment.paidAt || new Date(),
    metadata: {
      source: options.source || "payment_verification",
      paymentStatus: payment.status,
      paymentId: payment._id?.toString?.() || "",
    },
  };

  const update = {
    $set: baseSet,
    $setOnInsert: {
      eligibleAt: null,
      paidOutAt: null,
      payoutReference: "",
      reversedAt: null,
      reversalReason: "",
    },
  };
  return HostPayoutLedger.findOneAndUpdate({ paymentId: payment._id }, update, {
    upsert: true,
    new: true,
    setDefaultsOnInsert: true,
  });
};

const grantAdmissionForPaidPayment = async (payment) => {
  if (!payment || payment.admissionStatus !== "pending_payment") return;
  const event = await Event.findById(payment.eventId);
  if (!event) return;

  if (!Array.isArray(event.participants)) {
    event.participants = [];
  }

  const participantIndex = event.participants.findIndex(
    (p) => p?.userId?.toString() === payment.userId.toString()
  );

  if (participantIndex === -1) {
    event.participants.push({
      userId: payment.userId,
      status: "going",
      joinedAt: new Date(),
    });
  } else {
    event.participants[participantIndex].status = "going";
    if (!event.participants[participantIndex].joinedAt) {
      event.participants[participantIndex].joinedAt = new Date();
    }
  }

  await event.save();
  payment.admissionStatus = "admitted";
};

const ensureFeePolicy = async () => {
  return FeePolicy.findOneAndUpdate(
    { singletonKey: "default" },
    { $setOnInsert: { singletonKey: "default" } },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
};

const computeQuote = ({ baseAmount, feePolicy }) => {
  const base = Math.max(0, Number(baseAmount) || 0);
  const appFeeType = feePolicy?.appFeeType || "percentage";
  const appFeeValue = Number(feePolicy?.appFeeValue) || 0;
  const appFeeFlatAmount = Number(feePolicy?.appFeeFlatAmount) || 0;

  let appFee = 0;
  if (appFeeType === "percentage") {
    appFee = Math.round((base * appFeeValue) / 100);
  } else if (appFeeType === "flat") {
    appFee = Math.round(appFeeValue);
  } else {
    appFee = Math.round((base * appFeeValue) / 100) + Math.round(appFeeFlatAmount);
  }

  const minFee = Number(feePolicy?.minFeeAmount) || 0;
  const maxFee = Number(feePolicy?.maxFeeAmount) || 0;
  if (appFee < minFee) appFee = minFee;
  if (maxFee > 0 && appFee > maxFee) appFee = maxFee;

  const taxRatePercent = Number(feePolicy?.taxRatePercent) || 0;
  const taxAmount = taxRatePercent > 0 ? Math.round((appFee * taxRatePercent) / 100) : 0;

  // Provider processing fees are provider-specific; keep zero until provider adapter supports estimates.
  const processingFeeEstimate = 0;
  const totalAmount = base + appFee + processingFeeEstimate + taxAmount;

  return {
    baseAmount: base,
    appFee,
    processingFeeEstimate,
    taxAmount,
    totalAmount,
  };
};

const createQuote = async ({ eventId, userId, couponCode }) => {
  if (!mongoose.Types.ObjectId.isValid(eventId) || !mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid ID format");
    err.status = 400;
    throw err;
  }

  const event = await Event.findById(eventId).lean();
  if (!event) {
    const err = new Error("Event not found");
    err.status = 404;
    throw err;
  }
  if (!event.isPaid) {
    const err = new Error("This event is not paid");
    err.status = 400;
    throw err;
  }

  const feePolicy = await ensureFeePolicy();
  const quote = computeQuote({ baseAmount: event.priceAmount, feePolicy });
  const quoteId = `quote_${crypto.randomBytes(12).toString("hex")}`;
  const expiresAt = Date.now() + QUOTE_TTL_MS;

  quoteStore.set(quoteId, {
    eventId: eventId.toString(),
    userId: userId.toString(),
    couponCode: couponCode || "",
    currency: event.currency || "ZAR",
    ...quote,
    expiresAt,
  });

  return {
    quoteId,
    currency: event.currency || "ZAR",
    expiresAt,
    ...quote,
  };
};

const readValidQuote = ({ quoteId, eventId, userId }) => {
  const record = quoteStore.get(quoteId);
  if (!record) return null;
  if (record.expiresAt < Date.now()) {
    quoteStore.delete(quoteId);
    return null;
  }
  if (record.eventId !== eventId.toString() || record.userId !== userId.toString()) {
    return null;
  }
  return record;
};

const normalizePaymentStatus = (value) => {
  const raw = String(value || "").toLowerCase();
  if (SUCCESS_STATES.has(raw)) return "paid";
  if (raw === "failed") return "failed";
  if (raw === "expired") return "expired";
  return "pending";
};

const findActiveCheckout = async ({ eventId, userId }) => {
  const now = new Date();
  return EventPayment.findOne({
    eventId,
    userId,
    status: { $in: Array.from(ACTIVE_CHECKOUT_STATUSES) },
    "providerPayload.holdOnly": { $ne: true },
    $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
  }).sort({ createdAt: -1 });
};

const initializePayment = async ({ eventId, userId, quoteId, callbackUrl }) => {
  if (!mongoose.Types.ObjectId.isValid(eventId) || !mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid ID format");
    err.status = 400;
    throw err;
  }

  const event = await Event.findById(eventId).lean();
  if (!event) {
    const err = new Error("Event not found");
    err.status = 404;
    throw err;
  }
  if (!event.isPaid) {
    const err = new Error("This event is not paid");
    err.status = 400;
    throw err;
  }

  const hostPayoutProfile = await HostPayoutProfile.findOne({ userId: event.hostId }).lean();
  if (!hostPayoutProfile || hostPayoutProfile.status !== "active") {
    const err = new Error("Host payout profile is not active");
    err.status = 400;
    throw err;
  }

  const quote = readValidQuote({ quoteId, eventId, userId });
  if (!quote) {
    const err = new Error("Invalid or expired quote");
    err.status = 400;
    throw err;
  }

  const activeCheckout = await findActiveCheckout({ eventId, userId });
  if (activeCheckout) {
    try {
      await attachOpenPaidCheckoutSeatHold({ eventId, userId });
    } catch (attachErr) {
      if (attachErr.status === 409) {
        const err = new Error("Event is full");
        err.status = 409;
        throw err;
      }
      throw attachErr;
    }
    if (
      event.isPaid &&
      !event.requiresApproval &&
      activeCheckout.admissionStatus !== "pending_payment"
    ) {
      activeCheckout.admissionStatus = "pending_payment";
      await activeCheckout.save();
    }
    return {
      paymentId: activeCheckout._id,
      provider: activeCheckout.provider,
      reference: activeCheckout.providerReference,
      authorizationUrl:
        activeCheckout.providerPayload?.link ||
        activeCheckout.providerPayload?.checkoutUrl ||
        activeCheckout.providerPayload?.authorizationUrl ||
        activeCheckout.providerPayload?.url ||
        "",
      accessCode: activeCheckout.providerPayload?.accessCode || "",
      status: activeCheckout.status,
      reused: true,
    };
  }

  const user = await User.findById(userId).select("email name").lean();
  if (!user) {
    const err = new Error("User not found");
    err.status = 404;
    throw err;
  }

  const providerName = getActiveProviderName();
  const provider = getPaymentProvider(providerName);
  const providerResult = await provider.initializeTransaction({
    eventId: event._id.toString(),
    userId: userId.toString(),
    amount: quote.totalAmount,
    currency: quote.currency,
    email: user.email,
    name: user.name || "",
    callbackUrl: callbackUrl || "",
    subaccountCode: hostPayoutProfile.providerAccountCode || "",
  });

  let admissionStatus = "none";
  if (event.isPaid) {
    if (!event.requiresApproval) {
      admissionStatus = "pending_payment";
    } else if (
      Array.isArray(event.participants) &&
      event.participants.some(
        (participant) =>
          participant?.userId?.toString() === userId.toString() &&
          participant?.status === "interested"
      )
    ) {
      admissionStatus = "pending_payment";
    }
  }

  const payment = await EventPayment.create({
    eventId: event._id,
    userId,
    hostId: event.hostId,
    provider: providerResult.provider || providerName,
    providerReference: providerResult.reference,
    status: "initialized",
    amount: quote.totalAmount,
    currency: quote.currency,
    baseAmount: quote.baseAmount,
    appFeeAmount: quote.appFee,
    processingFeeAmount: quote.processingFeeEstimate,
    taxAmount: quote.taxAmount,
    couponCode: quote.couponCode || "",
    quoteId,
    providerPayload: providerResult.payload || null,
    expiresAt: new Date(quote.expiresAt),
    admissionStatus,
  });

  try {
    await attachOpenPaidCheckoutSeatHold({ eventId, userId });
  } catch (attachErr) {
    if (attachErr.status === 409) {
      await EventPayment.findByIdAndDelete(payment._id);
      const err = new Error("Event is full");
      err.status = 409;
      throw err;
    }
    throw attachErr;
  }

  return {
    paymentId: payment._id,
    provider: payment.provider,
    reference: payment.providerReference,
    authorizationUrl: providerResult.authorizationUrl || "",
    accessCode: providerResult.accessCode || "",
    status: payment.status,
  };
};

const verifyPayment = async ({ eventId, reference }) => {
  if (!mongoose.Types.ObjectId.isValid(eventId)) {
    const err = new Error("Invalid event ID format");
    err.status = 400;
    throw err;
  }
  if (!reference) {
    const err = new Error("Reference is required");
    err.status = 400;
    throw err;
  }

  const payment = await EventPayment.findOne({
    eventId,
    providerReference: reference,
  });
  if (!payment) {
    const err = new Error("Payment not found");
    err.status = 404;
    throw err;
  }

  const provider = getPaymentProvider(payment.provider);
  const verification = await provider.verifyTransaction(reference);
  const normalizedStatus = normalizePaymentStatus(verification.status);

  const wasPaymentHold = payment.admissionStatus === "pending_payment";

  payment.status = normalizedStatus;
  if (normalizedStatus === "paid") {
    payment.paidAt = verification.paidAt || new Date();
    await grantAdmissionForPaidPayment(payment);
    await upsertLedgerForPayment(payment, { source: "verify_payment" });
  } else if (normalizedStatus === "failed") {
    payment.failedAt = new Date();
    if (wasPaymentHold) {
      payment.admissionStatus = "expired";
    }
  } else if (normalizedStatus === "expired") {
    if (wasPaymentHold) {
      payment.admissionStatus = "expired";
    }
  }
  payment.providerPayload = verification.payload || payment.providerPayload;
  await payment.save();

  if (wasPaymentHold && (normalizedStatus === "failed" || normalizedStatus === "expired")) {
    await removeInterestedHoldForPayment(payment);
  }

  return {
    provider: payment.provider,
    reference: payment.providerReference,
    status: payment.status,
    paidAt: payment.paidAt,
  };
};

const createRefund = async ({
  eventId,
  reference,
  requesterUserId,
  amount,
  reason = "",
  refundType = "ticket_only",
}) => {
  if (
    !mongoose.Types.ObjectId.isValid(eventId) ||
    !mongoose.Types.ObjectId.isValid(requesterUserId)
  ) {
    const err = new Error("Invalid ID format");
    err.status = 400;
    throw err;
  }
  if (!reference) {
    const err = new Error("Reference is required");
    err.status = 400;
    throw err;
  }

  const payment = await EventPayment.findOne({
    eventId,
    providerReference: reference,
  });
  if (!payment) {
    const err = new Error("Payment not found");
    err.status = 404;
    throw err;
  }
  if (payment.status !== "paid") {
    const err = new Error("Only paid payments can be refunded");
    err.status = 400;
    throw err;
  }

  const event = await Event.findById(eventId).select("hostId participants");
  if (!event) {
    const err = new Error("Event not found");
    err.status = 404;
    throw err;
  }

  const requesterId = String(requesterUserId);
  const isPayer = String(payment.userId) === requesterId;
  const isHost = String(event.hostId) === requesterId;
  if (!isPayer && !isHost) {
    const err = new Error("Only the payer or host can trigger a refund");
    err.status = 403;
    throw err;
  }

  const normalizedRefundType = String(refundType || "ticket_only").trim().toLowerCase();
  const ticketAmount = Math.max(
    0,
    Math.round(
      Number.isFinite(Number(payment.baseAmount)) ? Number(payment.baseAmount) : Number(payment.amount)
    )
  );
  const totalPaidAmount = Math.max(0, Math.round(Number(payment.amount) || 0));
  const requestedAmount = Number(amount);

  let refundAmount = 0;
  if (Number.isFinite(requestedAmount) && requestedAmount > 0) {
    refundAmount = Math.round(requestedAmount);
  } else if (normalizedRefundType === "ticket_only") {
    refundAmount = ticketAmount;
  } else if (normalizedRefundType === "full") {
    refundAmount = totalPaidAmount;
  } else if (normalizedRefundType === "custom") {
    const err = new Error("Custom refunds require a positive amount");
    err.status = 400;
    throw err;
  } else {
    const err = new Error("Invalid refundType. Use ticket_only, full, or custom");
    err.status = 400;
    throw err;
  }

  // Margin-safe policy: attendee-initiated refunds are capped at ticket-only.
  if (isPayer && !isHost) {
    if (normalizedRefundType === "full" || normalizedRefundType === "custom") {
      const err = new Error("Only hosts can request full or custom refunds");
      err.status = 403;
      throw err;
    }
    if (refundAmount > ticketAmount) {
      const err = new Error("Attendee refunds cannot exceed ticket amount");
      err.status = 403;
      throw err;
    }
  }

  if (refundAmount <= 0) {
    const err = new Error("Refund amount must be a positive number");
    err.status = 400;
    throw err;
  }
  if (refundAmount > totalPaidAmount) {
    const err = new Error("Refund amount cannot exceed paid amount");
    err.status = 400;
    throw err;
  }

  const provider = getPaymentProvider(payment.provider);
  const refundResult = await provider.refundTransaction({
    reference: payment.providerReference,
    amount: refundAmount,
    reason,
    eventId: String(payment.eventId),
    userId: String(payment.userId),
  });

  payment.status = "refunded";
  payment.refundedAt = refundResult.refundedAt || new Date();
  payment.providerPayload = {
    ...(payment.providerPayload || {}),
    refund: refundResult.payload || {
      reference: payment.providerReference,
      amount: refundAmount,
      reason: reason || "Event refund",
      refundType: normalizedRefundType,
      requestedBy: requesterId,
    },
  };

  if (payment.admissionStatus === "admitted" || payment.admissionStatus === "pending_payment") {
    payment.admissionStatus = "expired";
    const participantIndex = Array.isArray(event.participants)
      ? event.participants.findIndex(
          (participant) => participant?.userId?.toString() === payment.userId.toString()
        )
      : -1;
    if (participantIndex >= 0) {
      event.participants.splice(participantIndex, 1);
      await event.save();
    }
  }

  await payment.save();

  await HostPayoutLedger.findOneAndUpdate(
    { paymentId: payment._id },
    {
      $set: {
        status: "reversed",
        reversedAt: payment.refundedAt,
        reversalReason: reason || "Payment refunded",
        hostOwedAmount: 0,
      },
    },
    { new: true }
  );

  return {
    provider: payment.provider,
    reference: payment.providerReference,
    status: payment.status,
    refundedAt: payment.refundedAt,
    amount: refundAmount,
    refundType: normalizedRefundType,
  };
};

const applyForHostPayout = async ({ userId, payload }) => {
  console.log("[paymentService.applyForHostPayout] start", {
    userId,
    hasBusinessName: Boolean(payload?.businessName),
    hasSettlementBankCode: Boolean(payload?.settlementBankCode),
    hasAccountNumber: Boolean(payload?.accountNumber),
    hasContactEmail: Boolean(payload?.contactEmail),
    hasContactName: Boolean(payload?.contactName),
    hasContactPhone: Boolean(payload?.contactPhone),
  });
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid user ID format");
    err.status = 400;
    throw err;
  }

  const user = await User.findById(userId).select("profileVerification verified").lean();
  if (!user) {
    const err = new Error("User not found");
    err.status = 404;
    throw err;
  }

  const isVerified = user?.verified || user?.profileVerification?.status === "approved";
  if (!isVerified) {
    console.warn("[paymentService.applyForHostPayout] blocked_unverified_user", {
      userId,
      verified: Boolean(user?.verified),
      profileVerificationStatus: user?.profileVerification?.status || null,
    });
    const err = new Error("Profile verification is required before applying");
    err.status = 403;
    throw err;
  }

  const provider = getActiveProviderName();
  const profile = await HostPayoutProfile.findOneAndUpdate(
    { userId },
    {
      $set: {
        provider,
        status: "pending_review",
        businessName: payload.businessName || "",
        settlementBankCode: payload.settlementBankCode || "",
        accountNumber: payload.accountNumber || "",
        contactEmail: payload.contactEmail || "",
        contactName: payload.contactName || "",
        contactPhone: payload.contactPhone || "",
        metadata: payload.metadata || null,
        rejectionReason: "",
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  console.log("[paymentService.applyForHostPayout] saved", {
    userId,
    status: profile?.status,
    provider: profile?.provider,
  });
  return profile;
};

const getHostPayoutStatus = async ({ userId }) => {
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid user ID format");
    err.status = 400;
    throw err;
  }
  const profile = await HostPayoutProfile.findOne({ userId }).lean();
  if (!profile) {
    return {
      userId,
      status: "not_applied",
      provider: getActiveProviderName(),
    };
  }
  return {
    userId,
    status: normalizeHostPayoutStatus(profile.status),
    provider: profile.provider,
    providerAccountCode: profile.providerAccountCode || "",
    reviewedAt: profile.reviewedAt,
    rejectionReason: profile.rejectionReason || "",
  };
};

const approveHostPayout = async ({ userId, reviewerId }) => {
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid user ID format");
    err.status = 400;
    throw err;
  }
  const profile = await HostPayoutProfile.findOne({ userId });
  if (!profile) {
    const err = new Error("Payout application not found");
    err.status = 404;
    throw err;
  }

  const provider = getPaymentProvider(profile.provider || getActiveProviderName());
  const providerAccount = await provider.createSubaccount({
    businessName: profile.businessName,
    settlementBankCode: profile.settlementBankCode,
    accountNumber: profile.accountNumber,
    contactEmail: profile.contactEmail,
    contactName: profile.contactName,
    contactPhone: profile.contactPhone,
    metadata: profile.metadata,
  });

  profile.status = providerAccount.status === "active" ? "active" : "action_required";
  profile.providerAccountCode = providerAccount.accountCode || "";
  profile.providerPayload = providerAccount.payload || null;
  profile.rejectionReason = "";
  profile.reviewedAt = new Date();
  profile.reviewedBy =
    reviewerId && mongoose.Types.ObjectId.isValid(reviewerId)
      ? reviewerId
      : null;
  await profile.save();

  return profile;
};

const rejectHostPayout = async ({ userId, reviewerId, reason }) => {
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid user ID format");
    err.status = 400;
    throw err;
  }
  const profile = await HostPayoutProfile.findOne({ userId });
  if (!profile) {
    const err = new Error("Payout application not found");
    err.status = 404;
    throw err;
  }

  profile.status = "rejected";
  profile.rejectionReason = reason || "Application rejected";
  profile.reviewedAt = new Date();
  profile.reviewedBy =
    reviewerId && mongoose.Types.ObjectId.isValid(reviewerId)
      ? reviewerId
      : null;
  await profile.save();

  return profile;
};

const listHostPayoutApplications = async ({
  status = "pending_review",
  page = 1,
  limit = 20,
}) => {
  const normalizedPage = Math.max(1, Number(page) || 1);
  const normalizedLimit = Math.min(100, Math.max(1, Number(limit) || 20));
  const query = {};

  if (status && status !== "all") {
    query.status = status;
  }

  const [items, total] = await Promise.all([
    HostPayoutProfile.find(query)
      .sort({ updatedAt: -1 })
      .skip((normalizedPage - 1) * normalizedLimit)
      .limit(normalizedLimit)
      .populate("userId", "name email profileImages verified profileVerification")
      .lean(),
    HostPayoutProfile.countDocuments(query),
  ]);

  return {
    items,
    pagination: {
      page: normalizedPage,
      limit: normalizedLimit,
      total,
      pages: Math.ceil(total / normalizedLimit),
    },
  };
};

const handleProviderWebhook = async ({
  providerName,
  rawBody,
  signature,
  parsedBody,
  webhookHeaders = {},
}) => {
  const provider = getPaymentProvider(providerName || getActiveProviderName());
  const secret =
    provider.getName() === "paystack"
      ? process.env.PAYSTACK_SECRET_KEY
      : provider.getName() === "stitch"
        ? process.env.STITCH_WEBHOOK_SECRET
        : provider.getName() === "yoco"
          ? process.env.YOCO_WEBHOOK_SECRET
        : "mock";
  const isValid = provider.verifyWebhookSignature(
    rawBody,
    signature,
    secret,
    webhookHeaders
  );
  if (!isValid) {
    const err = new Error("Invalid webhook signature");
    err.status = 401;
    throw err;
  }

  const event = provider.parseWebhookEvent(rawBody || parsedBody);
  if (!event.reference) {
    return { processed: false, reason: "no_reference" };
  }

  const payment = await EventPayment.findOne({
    provider: provider.getName(),
    providerReference: event.reference,
  });
  let resolvedPayment = payment;
  if (!resolvedPayment && provider.getName() === "yoco") {
    const webhookPayload = event.payload?.payload || event.payload?.data || {};
    const yocoPaymentId = webhookPayload?.id || "";
    const yocoMerchantReference =
      webhookPayload?.metadata?.merchantReference ||
      webhookPayload?.metadata?.externalId ||
      "";
    if (yocoMerchantReference) {
      resolvedPayment = await EventPayment.findOne({
        provider: provider.getName(),
        "providerPayload.merchantReference": yocoMerchantReference,
      });
    }
    if (!resolvedPayment && yocoPaymentId) {
      resolvedPayment = await EventPayment.findOne({
        provider: provider.getName(),
        $or: [
          { "providerPayload.paymentId": yocoPaymentId },
          { "providerPayload.id": yocoPaymentId },
        ],
      });
    }
  }
  if (!resolvedPayment) {
    return { processed: false, reason: "payment_not_found", reference: event.reference };
  }

  if (
    resolvedPayment.webhookEventId &&
    resolvedPayment.webhookEventId === `${event.eventType}:${event.reference}`
  ) {
    return { processed: false, reason: "duplicate", reference: event.reference };
  }

  const normalizedStatus = normalizePaymentStatus(event.status);
  const wasPaymentHold = resolvedPayment.admissionStatus === "pending_payment";

  if (normalizedStatus === "paid") {
    resolvedPayment.status = "paid";
    resolvedPayment.paidAt = resolvedPayment.paidAt || new Date();
    resolvedPayment.providerPayload = {
      ...(resolvedPayment.providerPayload || {}),
      ...(event.payload || {}),
      paymentId:
        event.payload?.payload?.id ||
        event.payload?.data?.id ||
        resolvedPayment.providerPayload?.paymentId ||
        "",
    };
    await grantAdmissionForPaidPayment(resolvedPayment);
    await upsertLedgerForPayment(resolvedPayment, { source: "provider_webhook" });
  } else if (normalizedStatus === "failed") {
    resolvedPayment.status = "failed";
    resolvedPayment.failedAt = new Date();
    if (wasPaymentHold) {
      resolvedPayment.admissionStatus = "expired";
    }
  } else if (normalizedStatus === "expired") {
    resolvedPayment.status = "expired";
    resolvedPayment.admissionStatus =
      resolvedPayment.admissionStatus === "pending_payment"
        ? "expired"
        : resolvedPayment.admissionStatus;
  }
  resolvedPayment.webhookEventId = `${event.eventType}:${event.reference}`;
  resolvedPayment.providerPayload = {
    ...(resolvedPayment.providerPayload || {}),
    ...(event.payload || {}),
    paymentId:
      event.payload?.payload?.id ||
      event.payload?.data?.id ||
      resolvedPayment.providerPayload?.paymentId ||
      "",
  };
  await resolvedPayment.save();

  if (wasPaymentHold && (normalizedStatus === "failed" || normalizedStatus === "expired")) {
    await removeInterestedHoldForPayment(resolvedPayment);
  }

  return {
    processed: true,
    reference: event.reference,
    status: resolvedPayment.status,
  };
};

const getPaymentStatus = async ({ eventId, userId }) => {
  if (!mongoose.Types.ObjectId.isValid(eventId) || !mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid ID format");
    err.status = 400;
    throw err;
  }

  const payment = await EventPayment.findOne({ eventId, userId }).sort({ createdAt: -1 }).lean();
  if (!payment) {
    return {
      hasPayment: false,
      status: "none",
      admissionStatus: "none",
      expiresAt: null,
      paidAt: null,
      reference: "",
    };
  }

  return {
    hasPayment: true,
    status: payment.status,
    admissionStatus: payment.admissionStatus || "none",
    expiresAt: payment.expiresAt,
    paidAt: payment.paidAt,
    reference: payment.providerReference,
  };
};

const markEventPayoutsEligible = async ({ eventId }) => {
  if (!mongoose.Types.ObjectId.isValid(eventId)) {
    const err = new Error("Invalid event ID format");
    err.status = 400;
    throw err;
  }

  const event = await Event.findById(eventId).select("status");
  if (!event) {
    const err = new Error("Event not found");
    err.status = 404;
    throw err;
  }
  if (event.status !== "ended") {
    return { updatedCount: 0, skipped: true, reason: "event_not_ended" };
  }

  const result = await HostPayoutLedger.updateMany(
    {
      eventId,
      status: { $in: ["accrued", "on_hold"] },
    },
    {
      $set: {
        status: "eligible",
        eligibleAt: new Date(),
      },
    }
  );

  return {
    updatedCount: result.modifiedCount || 0,
    matchedCount: result.matchedCount || 0,
  };
};

const buildLedgerFilterQuery = ({ status, hostId, eventId, fromDate, toDate, payoutReference = "" }) => {
  const query = {};
  const normalizedStatus = normalizeLedgerStatus(status);
  if (normalizedStatus) {
    query.status = normalizedStatus;
  }
  if (hostId) {
    if (!mongoose.Types.ObjectId.isValid(hostId)) {
      const err = new Error("Invalid host ID format");
      err.status = 400;
      throw err;
    }
    query.hostId = hostId;
  }
  if (eventId) {
    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      const err = new Error("Invalid event ID format");
      err.status = 400;
      throw err;
    }
    query.eventId = eventId;
  }

  const createdAt = {};
  const startDate = normalizeDateInput(fromDate, { endOfDay: false });
  const endDate = normalizeDateInput(toDate, { endOfDay: true });
  if (startDate) createdAt.$gte = startDate;
  if (endDate) createdAt.$lte = endDate;
  if (Object.keys(createdAt).length) {
    query.createdAt = createdAt;
  }

  const normalizedPayoutReference = String(payoutReference || "").trim();
  if (normalizedPayoutReference) {
    query.payoutReference = { $regex: normalizedPayoutReference, $options: "i" };
  }

  return query;
};

const listHostPayoutLedgerEntries = async ({
  status = "",
  hostId = "",
  eventId = "",
  fromDate = "",
  toDate = "",
  payoutReference = "",
  page = 1,
  limit = 20,
  sortBy = "createdAt",
  sortOrder = -1,
}) => {
  const normalizedPage = Math.max(1, Number(page) || 1);
  const normalizedLimit = Math.min(100, Math.max(1, Number(limit) || 20));
  const normalizedSortBy = LEDGER_SORT_FIELDS.has(sortBy) ? sortBy : "createdAt";
  const normalizedSortOrder = normalizeSortOrder(sortOrder);
  const query = buildLedgerFilterQuery({
    status,
    hostId,
    eventId,
    fromDate,
    toDate,
    payoutReference,
  });

  const [items, total] = await Promise.all([
    HostPayoutLedger.find(query)
      .sort({ [normalizedSortBy]: normalizedSortOrder })
      .skip((normalizedPage - 1) * normalizedLimit)
      .limit(normalizedLimit)
      .populate("hostId", "name email")
      .populate("payerUserId", "name email")
      .populate("eventId", "title startTime status")
      .populate("paymentId", "providerReference amount currency status paidAt")
      .lean(),
    HostPayoutLedger.countDocuments(query),
  ]);

  return {
    items,
    pagination: {
      page: normalizedPage,
      limit: normalizedLimit,
      total,
      pages: Math.ceil(total / normalizedLimit),
    },
  };
};

const getHostPayoutLedgerGlobalSummary = async ({
  hostId = "",
  fromDate = "",
  toDate = "",
  payoutReference = "",
}) => {
  const match = buildLedgerFilterQuery({
    hostId,
    fromDate,
    toDate,
    payoutReference,
  });

  const rows = await HostPayoutLedger.aggregate([
    { $match: match },
    {
      $group: {
        _id: "$status",
        totalHostOwed: { $sum: "$hostOwedAmount" },
        totalGross: { $sum: "$grossAmount" },
        totalPlatformCommission: { $sum: "$platformCommissionAmount" },
        totalProviderFees: { $sum: "$providerFeeAmount" },
        totalTax: { $sum: "$taxAmount" },
        count: { $sum: 1 },
      },
    },
  ]);

  const byStatus = {
    accrued: { count: 0, totalHostOwed: 0, totalGross: 0, totalPlatformCommission: 0, totalProviderFees: 0, totalTax: 0 },
    on_hold: { count: 0, totalHostOwed: 0, totalGross: 0, totalPlatformCommission: 0, totalProviderFees: 0, totalTax: 0 },
    eligible: { count: 0, totalHostOwed: 0, totalGross: 0, totalPlatformCommission: 0, totalProviderFees: 0, totalTax: 0 },
    paid_out: { count: 0, totalHostOwed: 0, totalGross: 0, totalPlatformCommission: 0, totalProviderFees: 0, totalTax: 0 },
    reversed: { count: 0, totalHostOwed: 0, totalGross: 0, totalPlatformCommission: 0, totalProviderFees: 0, totalTax: 0 },
  };

  rows.forEach((row) => {
    if (!byStatus[row._id]) return;
    byStatus[row._id] = {
      count: Number(row.count) || 0,
      totalHostOwed: toMoney(row.totalHostOwed),
      totalGross: toMoney(row.totalGross),
      totalPlatformCommission: toMoney(row.totalPlatformCommission),
      totalProviderFees: toMoney(row.totalProviderFees),
      totalTax: toMoney(row.totalTax),
    };
  });

  const totals = Object.values(byStatus).reduce(
    (acc, row) => ({
      totalCount: acc.totalCount + row.count,
      totalHostOwed: acc.totalHostOwed + row.totalHostOwed,
      totalGross: acc.totalGross + row.totalGross,
      totalPlatformCommission: acc.totalPlatformCommission + row.totalPlatformCommission,
      totalProviderFees: acc.totalProviderFees + row.totalProviderFees,
      totalTax: acc.totalTax + row.totalTax,
    }),
    {
      totalCount: 0,
      totalHostOwed: 0,
      totalGross: 0,
      totalPlatformCommission: 0,
      totalProviderFees: 0,
      totalTax: 0,
    }
  );

  return {
    filters: {
      hostId: hostId || "",
      fromDate: fromDate || "",
      toDate: toDate || "",
      payoutReference: payoutReference || "",
    },
    byStatus,
    totals,
  };
};

const getHostPayoutLedgerSummary = async ({ userId }) => {
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid user ID format");
    err.status = 400;
    throw err;
  }

  const rows = await HostPayoutLedger.aggregate([
    {
      $match: { hostId: new mongoose.Types.ObjectId(userId) },
    },
    {
      $group: {
        _id: "$status",
        totalHostOwed: { $sum: "$hostOwedAmount" },
        totalGross: { $sum: "$grossAmount" },
        count: { $sum: 1 },
      },
    },
  ]);

  const summary = {
    on_hold: { count: 0, totalHostOwed: 0, totalGross: 0 },
    eligible: { count: 0, totalHostOwed: 0, totalGross: 0 },
    paid_out: { count: 0, totalHostOwed: 0, totalGross: 0 },
    reversed: { count: 0, totalHostOwed: 0, totalGross: 0 },
  };
  for (const row of rows) {
    if (!summary[row._id]) continue;
    summary[row._id] = {
      count: Number(row.count) || 0,
      totalHostOwed: toMoney(row.totalHostOwed),
      totalGross: toMoney(row.totalGross),
    };
  }

  return {
    userId,
    summary,
    totals: {
      availableToPayout: summary.eligible.totalHostOwed,
      onHold: summary.on_hold.totalHostOwed,
      paidOut: summary.paid_out.totalHostOwed,
    },
  };
};

const settleEligibleHostPayouts = async ({ userId, payoutReference = "", eventId = "" }) => {
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    const err = new Error("Invalid user ID format");
    err.status = 400;
    throw err;
  }

  const query = {
    hostId: userId,
    status: "eligible",
  };
  if (eventId) {
    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      const err = new Error("Invalid event ID format");
      err.status = 400;
      throw err;
    }
    query.eventId = eventId;
  }

  const rows = await HostPayoutLedger.find(query).select("_id hostOwedAmount");
  if (!rows.length) {
    return {
      settledCount: 0,
      settledAmount: 0,
      payoutReference: payoutReference || "",
    };
  }

  const settledAmount = rows.reduce((sum, row) => sum + toMoney(row.hostOwedAmount), 0);
  const finalPayoutReference =
    String(payoutReference || "").trim() || `PAYOUT_${crypto.randomBytes(8).toString("hex")}`;

  const ids = rows.map((row) => row._id);
  await HostPayoutLedger.updateMany(
    { _id: { $in: ids } },
    {
      $set: {
        status: "paid_out",
        paidOutAt: new Date(),
        payoutReference: finalPayoutReference,
      },
    }
  );

  return {
    settledCount: rows.length,
    settledAmount,
    payoutReference: finalPayoutReference,
  };
};

module.exports = {
  ensureFeePolicy,
  createQuote,
  initializePayment,
  verifyPayment,
  createRefund,
  getPaymentStatus,
  markEventPayoutsEligible,
  listHostPayoutLedgerEntries,
  getHostPayoutLedgerGlobalSummary,
  getHostPayoutLedgerSummary,
  settleEligibleHostPayouts,
  applyForHostPayout,
  getHostPayoutStatus,
  approveHostPayout,
  rejectHostPayout,
  listHostPayoutApplications,
  handleProviderWebhook,
};
