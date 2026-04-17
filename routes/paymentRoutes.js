const express = require("express");
const {
  createQuote,
  initializePayment,
  verifyPayment,
  applyForHostPayout,
  getHostPayoutStatus,
  approveHostPayout,
  rejectHostPayout,
  listHostPayoutApplications,
  handleProviderWebhook,
} = require("../services/paymentService");

const ensureAuthAndUserMatch = ({ source = "body", userKey = "userId" } = {}) => {
  return (req, res, next) => {
    if (!req.authUserId) {
      return res.status(401).json({ message: "Authentication required" });
    }
    const requestUserId =
      source === "params"
        ? req.params?.[userKey]
        : source === "query"
        ? req.query?.[userKey]
        : req.body?.[userKey];

    if (!requestUserId) {
      return res.status(400).json({ message: `${userKey} is required` });
    }
    if (String(requestUserId) !== String(req.authUserId)) {
      return res.status(403).json({ message: "Forbidden for this user context" });
    }
    return next();
  };
};

module.exports = (requireAuth) => {
  const router = express.Router();
  const requireOwnBodyUser = [requireAuth, ensureAuthAndUserMatch({ source: "body" })];
  const requireOwnParamUser = [requireAuth, ensureAuthAndUserMatch({ source: "params" })];
  const requireOwnQueryUser = [requireAuth, ensureAuthAndUserMatch({ source: "query" })];

router.post("/host/payouts/apply", async (req, res) => {
  try {
    const { userId, ...payload } = req.body;
    console.log("[host/payouts/apply] incoming", {
      authUserId: req.authUserId,
      userId,
      payloadKeys: Object.keys(payload || {}),
      contactEmail: payload?.contactEmail || "",
      businessName: payload?.businessName || "",
    });
    const profile = await applyForHostPayout({ userId, payload });
    console.log("[host/payouts/apply] success", {
      userId,
      status: profile?.status,
      provider: profile?.provider,
    });
    return res.status(200).json({
      message: "Payout application submitted",
      status: profile.status,
      profile,
    });
  } catch (error) {
    console.error("[host/payouts/apply] failed", {
      authUserId: req.authUserId,
      userId: req.body?.userId,
      message: error?.message,
      status: error?.status || 500,
      stack: error?.stack,
    });
    return res.status(error.status || 500).json({
      message: error.message || "Failed to submit payout application",
    });
  }
});

router.get("/host/payouts/status/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const status = await getHostPayoutStatus({ userId });
    return res.status(200).json(status);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to fetch payout status",
    });
  }
});

router.get("/host/payouts/status", async (req, res) => {
  try {
    const userId = req.query.userId;
    const status = await getHostPayoutStatus({ userId });
    return res.status(200).json(status);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to fetch payout status",
    });
  }
});

router.post("/admin/host-payouts/:userId/approve", async (req, res) => {
  try {
    const { userId } = req.params;
    const reviewerId = req.body?.reviewerId || null;
    const profile = await approveHostPayout({ userId, reviewerId });
    return res.status(200).json({
      message: "Host payout profile approved",
      status: profile.status,
      profile,
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to approve payout profile",
    });
  }
});

router.post("/admin/host-payouts/:userId/reject", async (req, res) => {
  try {
    const { userId } = req.params;
    const reviewerId = req.body?.reviewerId || null;
    const reason = req.body?.reason || "Application rejected";
    const profile = await rejectHostPayout({ userId, reviewerId, reason });
    return res.status(200).json({
      message: "Host payout profile rejected",
      status: profile.status,
      profile,
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to reject payout profile",
    });
  }
});

router.get("/admin/host-payouts", requireAuth, async (req, res) => {
  try {
    const { status = "pending_review", page = 1, limit = 20 } = req.query;
    const result = await listHostPayoutApplications({ status, page, limit });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to fetch host payout applications",
    });
  }
});

router.post("/events/:eventId/payments/quote", ...requireOwnBodyUser, async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, couponCode = "" } = req.body;
    const quote = await createQuote({ eventId, userId, couponCode });
    return res.status(200).json(quote);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to create payment quote",
    });
  }
});

router.post("/events/:eventId/payments/initialize", ...requireOwnBodyUser, async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, quoteId, callbackUrl = "" } = req.body;
    const result = await initializePayment({
      eventId,
      userId,
      quoteId,
      callbackUrl,
    });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to initialize payment",
    });
  }
});

router.get("/events/:eventId/payments/verify/:reference", requireAuth, async (req, res) => {
  try {
    const { eventId, reference } = req.params;
    const result = await verifyPayment({ eventId, reference });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to verify payment",
    });
  }
});

router.post("/webhooks/payments/:provider", async (req, res) => {
  try {
    const providerName = req.params.provider;
    const rawBody =
      req.rawBody ||
      (typeof req.body === "string" ? req.body : JSON.stringify(req.body || {}));
    const signature = req.headers["x-paystack-signature"] || "";
    const result = await handleProviderWebhook({
      providerName,
      rawBody,
      signature,
      parsedBody: req.body,
    });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to process webhook",
    });
  }
});

router.post("/webhooks/paystack", async (req, res) => {
  try {
    const rawBody =
      req.rawBody ||
      (typeof req.body === "string" ? req.body : JSON.stringify(req.body || {}));
    const signature = req.headers["x-paystack-signature"] || "";
    const result = await handleProviderWebhook({
      providerName: "paystack",
      rawBody,
      signature,
      parsedBody: req.body,
    });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to process webhook",
    });
  }
});

  return router;
};
