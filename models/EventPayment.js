const mongoose = require("mongoose");

const eventPaymentSchema = new mongoose.Schema(
  {
    eventId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Event",
      required: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    hostId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    provider: {
      type: String,
      enum: ["mock", "paystack", "stitch", "yoco", "ozow"],
      default: "mock",
      index: true,
    },
    providerReference: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    status: {
      type: String,
      enum: [
        "initialized",
        "pending",
        "paid",
        "failed",
        "refunded",
        "expired",
      ],
      default: "initialized",
      index: true,
    },
    amount: { type: Number, required: true, min: 0 },
    currency: { type: String, required: true, uppercase: true, trim: true },
    baseAmount: { type: Number, required: true, min: 0 },
    appFeeAmount: { type: Number, required: true, min: 0 },
    processingFeeAmount: { type: Number, required: true, min: 0 },
    taxAmount: { type: Number, default: 0, min: 0 },
    couponCode: { type: String, default: "" },
    quoteId: { type: String, default: "" },
    idempotencyKey: { type: String, default: "" },
    providerPayload: { type: mongoose.Schema.Types.Mixed, default: null },
    webhookEventId: { type: String, default: "" },
    paidAt: { type: Date, default: null },
    failedAt: { type: Date, default: null },
    refundedAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null },
    admissionStatus: {
      type: String,
      enum: ["none", "pending_payment", "admitted", "expired"],
      default: "none",
      index: true,
    },
    ticketCode: {
      type: String,
      default: "",
      trim: true,
    },
    ticketStatus: {
      type: String,
      enum: ["none", "active", "scanned", "void"],
      default: "none",
      index: true,
    },
    ticketIssuedAt: { type: Date, default: null },
    ticketScannedAt: { type: Date, default: null },
    ticketScannedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
  },
  { timestamps: true }
);

eventPaymentSchema.index(
  { ticketCode: 1 },
  {
    unique: true,
    partialFilterExpression: {
      ticketCode: { $type: "string", $ne: "" },
    },
  }
);

eventPaymentSchema.index({ eventId: 1, userId: 1, createdAt: -1 });
eventPaymentSchema.index({ provider: 1, providerReference: 1 }, { unique: true });
eventPaymentSchema.index({ eventId: 1, userId: 1, status: 1, admissionStatus: 1 });

module.exports = mongoose.model("EventPayment", eventPaymentSchema);
