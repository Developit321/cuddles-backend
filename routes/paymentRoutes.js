const express = require("express");
const {
  createQuote,
  initializePayment,
  verifyPayment,
  createRefund,
  getPaymentStatus,
  getHostPayoutLedgerSummary,
  listHostPayoutLedgerEntries,
  getHostPayoutLedgerGlobalSummary,
  settleEligibleHostPayouts,
  applyForHostPayout,
  getHostPayoutStatus,
  listPaystackBanksForHost,
  approveHostPayout,
  rejectHostPayout,
  listHostPayoutApplications,
  handleProviderWebhook,
} = require("../services/paymentService");

module.exports = (requireAuth) => {
  const router = express.Router();

router.post("/host/payouts/apply", async (req, res) => {
  try {
    const { userId, ...payload } = req.body;
    console.log("[host/payouts/apply] incoming", {
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

/** Public proxy: Paystack bank directory only (no user PII). Avoids JWT mismatch when app talks to a different API host than login. */
router.get("/host/payouts/paystack/banks", async (req, res) => {
  try {
    const country = String(req.query.country || "south africa")
      .trim()
      .slice(0, 40);
    const banks = await listPaystackBanksForHost({ country });
    return res.status(200).json({ banks });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to list Paystack banks",
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

router.get("/host/payouts/ledger/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await getHostPayoutLedgerSummary({ userId });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to fetch host payout ledger",
    });
  }
});

router.get("/admin/host-payouts/ledger", requireAuth, async (req, res) => {
  try {
    const {
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
    } = req.query || {};
    const result = await listHostPayoutLedgerEntries({
      status,
      hostId,
      eventId,
      fromDate,
      toDate,
      payoutReference,
      page,
      limit,
      sortBy,
      sortOrder,
    });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to fetch host payout ledger entries",
    });
  }
});

router.get("/admin/host-payouts/ledger/summary", requireAuth, async (req, res) => {
  try {
    const { hostId = "", fromDate = "", toDate = "", payoutReference = "" } = req.query || {};
    const result = await getHostPayoutLedgerGlobalSummary({
      hostId,
      fromDate,
      toDate,
      payoutReference,
    });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to fetch host payout ledger summary",
    });
  }
});

router.post("/admin/host-payouts/:userId/settle", requireAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { payoutReference = "", eventId = "" } = req.body || {};
    const result = await settleEligibleHostPayouts({ userId, payoutReference, eventId });
    return res.status(200).json({
      message: "Eligible host payouts settled",
      ...result,
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to settle host payouts",
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

router.post("/events/:eventId/payments/quote", async (req, res) => {
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

router.post("/events/:eventId/payments/initialize", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, quoteId, callbackUrl = "" } = req.body;
    console.log("[payments/initialize] incoming", {
      eventId,
      userId,
      quoteId,
      hasCallbackUrl: Boolean(callbackUrl),
    });
    const result = await initializePayment({
      eventId,
      userId,
      quoteId,
      callbackUrl,
    });
    console.log("[payments/initialize] success", {
      eventId,
      userId,
      provider: result?.provider,
      reference: result?.reference,
      hasAuthorizationUrl: Boolean(result?.authorizationUrl),
    });
    return res.status(200).json(result);
  } catch (error) {
    console.error("[payments/initialize] failed", {
      eventId: req.params?.eventId,
      userId: req.body?.userId,
      quoteId: req.body?.quoteId,
      message: error?.message,
      status: error?.status || error?.response?.status || 500,
      responseData: error?.response?.data || null,
    });
    return res.status(error.status || 500).json({
      message: error.message || "Failed to initialize payment",
    });
  }
});

router.get("/events/:eventId/payments/verify/:reference", async (req, res) => {
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

router.post("/events/:eventId/payments/refund/:reference", async (req, res) => {
  try {
    const { eventId, reference } = req.params;
    const { requesterUserId, amount, reason = "", refundType = "ticket_only" } = req.body;
    const result = await createRefund({
      eventId,
      reference,
      requesterUserId,
      amount,
      reason,
      refundType,
    });
    return res.status(200).json(result);
  } catch (error) {
    return res.status(error.status || 500).json({
      message: error.message || "Failed to create refund",
    });
  }
});

router.get(
  "/events/:eventId/payments/status/:userId",
  async (req, res) => {
    try {
      const { eventId, userId } = req.params;
      const result = await getPaymentStatus({ eventId, userId });
      return res.status(200).json(result);
    } catch (error) {
      return res.status(error.status || 500).json({
        message: error.message || "Failed to fetch payment status",
      });
    }
  }
);

router.post("/webhooks/payments/:provider", async (req, res) => {
  try {
    const providerName = req.params.provider;
    const rawBody =
      req.rawBody ||
      (typeof req.body === "string" ? req.body : JSON.stringify(req.body || {}));
    const signature =
      req.headers["svix-signature"] ||
      req.headers["webhook-signature"] ||
      req.headers["x-stitch-signature"] ||
      req.headers["x-paystack-signature"] ||
      req.headers["x-yoco-signature"] ||
      req.headers["x-ozow-signature"] ||
      req.headers["x-ozow-hash"] ||
      "";
    const result = await handleProviderWebhook({
      providerName,
      rawBody,
      signature,
      parsedBody: req.body,
      webhookHeaders: {
        svixId: req.headers["svix-id"] || "",
        svixTimestamp: req.headers["svix-timestamp"] || "",
        webhookId: req.headers["webhook-id"] || "",
        webhookTimestamp: req.headers["webhook-timestamp"] || "",
      },
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
