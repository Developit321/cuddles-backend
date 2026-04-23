const crypto = require("crypto");
const mongoose = require("mongoose");
const Event = require("../models/Event");
const User = require("../models/User");
const EventPayment = require("../models/EventPayment");
const FeePolicy = require("../models/FeePolicy");
const HostPayoutProfile = require("../models/HostPayoutProfile");
const { getActiveProviderName, getPaymentProvider } = require("../payments/providerRegistry");

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
    admissionStatus:
      event.requiresApproval &&
      Array.isArray(event.participants) &&
      event.participants.some(
        (participant) =>
          participant?.userId?.toString() === userId.toString() &&
          participant?.status === "interested"
      )
        ? "pending_payment"
        : "none",
  });

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

  payment.status = normalizedStatus;
  if (normalizedStatus === "paid") {
    payment.paidAt = verification.paidAt || new Date();
    await grantAdmissionForPaidPayment(payment);
  } else if (normalizedStatus === "expired") {
    payment.admissionStatus =
      payment.admissionStatus === "pending_payment" ? "expired" : payment.admissionStatus;
  }
  payment.providerPayload = verification.payload || payment.providerPayload;
  await payment.save();

  return {
    provider: payment.provider,
    reference: payment.providerReference,
    status: payment.status,
    paidAt: payment.paidAt,
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
}) => {
  const provider = getPaymentProvider(providerName || getActiveProviderName());
  const secret =
    provider.getName() === "paystack"
      ? process.env.PAYSTACK_SECRET_KEY
      : provider.getName() === "stitch"
        ? process.env.STITCH_WEBHOOK_SECRET
        : "mock";
  const isValid = provider.verifyWebhookSignature(rawBody, signature, secret);
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
  if (!payment) {
    return { processed: false, reason: "payment_not_found", reference: event.reference };
  }

  if (payment.webhookEventId && payment.webhookEventId === `${event.eventType}:${event.reference}`) {
    return { processed: false, reason: "duplicate", reference: event.reference };
  }

  const normalizedStatus = normalizePaymentStatus(event.status);
  if (normalizedStatus === "paid") {
    payment.status = "paid";
    payment.paidAt = payment.paidAt || new Date();
    await grantAdmissionForPaidPayment(payment);
  } else if (normalizedStatus === "failed") {
    payment.status = "failed";
    payment.failedAt = new Date();
  } else if (normalizedStatus === "expired") {
    payment.status = "expired";
    payment.admissionStatus =
      payment.admissionStatus === "pending_payment" ? "expired" : payment.admissionStatus;
  }
  payment.webhookEventId = `${event.eventType}:${event.reference}`;
  payment.providerPayload = event.payload || payment.providerPayload;
  await payment.save();

  return {
    processed: true,
    reference: event.reference,
    status: payment.status,
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

module.exports = {
  ensureFeePolicy,
  createQuote,
  initializePayment,
  verifyPayment,
  getPaymentStatus,
  applyForHostPayout,
  getHostPayoutStatus,
  approveHostPayout,
  rejectHostPayout,
  listHostPayoutApplications,
  handleProviderWebhook,
};
