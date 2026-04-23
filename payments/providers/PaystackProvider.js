const crypto = require("crypto");
const PaymentProvider = require("./PaymentProvider");

class PaystackProvider extends PaymentProvider {
  getName() {
    return "paystack";
  }

  async createSubaccount() {
    throw new Error("PaystackProvider.createSubaccount is not wired yet");
  }

  async initializeTransaction(payload = {}) {
    // Contract-compatible stub until live Paystack integration is enabled.
    const reference = `PSTK_STUB_${crypto.randomBytes(8).toString("hex")}`;
    return {
      provider: this.getName(),
      reference,
      authorizationUrl: payload.callbackUrl || "",
      accessCode: "",
      status: "pending",
      payload,
    };
  }

  async verifyTransaction(reference) {
    return {
      provider: this.getName(),
      reference,
      status: "pending",
      paidAt: null,
      payload: { stub: true },
    };
  }

  verifyWebhookSignature(rawBody, signature, secretKey) {
    if (!signature || !secretKey) return false;
    const hash = crypto
      .createHmac("sha512", secretKey)
      .update(rawBody)
      .digest("hex");
    return hash === signature;
  }

  parseWebhookEvent(rawBody) {
    const event = typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody || {};
    return {
      eventType: event.event || "",
      reference: event.data?.reference || "",
      status: event.data?.status || "",
      payload: event,
    };
  }
}

module.exports = PaystackProvider;
