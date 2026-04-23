const crypto = require("crypto");
const PaymentProvider = require("./PaymentProvider");

class MockProvider extends PaymentProvider {
  getName() {
    return "mock";
  }

  async createSubaccount(payload = {}) {
    const code = `MOCK_SUB_${crypto.randomBytes(6).toString("hex")}`;
    return {
      provider: this.getName(),
      accountCode: code,
      status: "active",
      payload: {
        ...payload,
        accountCode: code,
      },
    };
  }

  async initializeTransaction(payload = {}) {
    const reference = `MOCK_TX_${crypto.randomBytes(8).toString("hex")}`;
    return {
      provider: this.getName(),
      reference,
      authorizationUrl: `https://mock-payments.local/checkout/${reference}`,
      accessCode: `mock_access_${crypto.randomBytes(8).toString("hex")}`,
      status: "pending",
      payload,
    };
  }

  async verifyTransaction(reference) {
    return {
      provider: this.getName(),
      reference,
      status: "paid",
      paidAt: new Date(),
      payload: { simulated: true },
    };
  }

  verifyWebhookSignature() {
    // Mock provider always accepts signatures.
    return true;
  }

  parseWebhookEvent(rawBody) {
    const event = typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody || {};
    return {
      eventType: event.event || "charge.success",
      reference: event.data?.reference || event.reference || "",
      status: event.data?.status || event.status || "success",
      payload: event,
    };
  }
}

module.exports = MockProvider;
