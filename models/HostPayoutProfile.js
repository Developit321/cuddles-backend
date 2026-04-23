const mongoose = require("mongoose");

const hostPayoutProfileSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
      index: true,
    },
    provider: {
      type: String,
      enum: ["mock", "paystack"],
      default: "mock",
      index: true,
    },
    status: {
      type: String,
      enum: [
        "not_applied",
        "pending_review",
        "action_required",
        "active",
        "rejected",
        "suspended",
      ],
      default: "not_applied",
      index: true,
    },
    businessName: { type: String, default: "" },
    settlementBankCode: { type: String, default: "" },
    accountNumber: { type: String, default: "" },
    contactEmail: { type: String, default: "" },
    contactName: { type: String, default: "" },
    contactPhone: { type: String, default: "" },
    providerAccountCode: { type: String, default: "" },
    providerPayload: { type: mongoose.Schema.Types.Mixed, default: null },
    rejectionReason: { type: String, default: "" },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    reviewedAt: { type: Date, default: null },
    metadata: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true }
);

hostPayoutProfileSchema.index({ userId: 1, status: 1 });

module.exports = mongoose.model("HostPayoutProfile", hostPayoutProfileSchema);
