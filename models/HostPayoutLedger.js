const mongoose = require("mongoose");

const hostPayoutLedgerSchema = new mongoose.Schema(
  {
    eventId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Event",
      required: true,
      index: true,
    },
    paymentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "EventPayment",
      required: true,
      unique: true,
      index: true,
    },
    hostId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    payerUserId: {
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
      default: "",
      index: true,
    },
    currency: {
      type: String,
      required: true,
      uppercase: true,
      trim: true,
    },
    grossAmount: { type: Number, required: true, min: 0 },
    platformCommissionAmount: { type: Number, required: true, min: 0 },
    providerFeeAmount: { type: Number, default: 0, min: 0 },
    taxAmount: { type: Number, default: 0, min: 0 },
    hostOwedAmount: { type: Number, required: true, min: 0 },
    status: {
      type: String,
      enum: ["accrued", "on_hold", "eligible", "paid_out", "reversed"],
      default: "accrued",
      index: true,
    },
    accruedAt: { type: Date, default: Date.now },
    eligibleAt: { type: Date, default: null },
    paidOutAt: { type: Date, default: null },
    payoutReference: { type: String, default: "" },
    reversedAt: { type: Date, default: null },
    reversalReason: { type: String, default: "" },
    metadata: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true }
);

hostPayoutLedgerSchema.index({ hostId: 1, status: 1, createdAt: -1 });
hostPayoutLedgerSchema.index({ eventId: 1, hostId: 1, status: 1 });

module.exports = mongoose.model("HostPayoutLedger", hostPayoutLedgerSchema);
