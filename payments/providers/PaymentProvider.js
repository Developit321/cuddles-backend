class PaymentProvider {
  getName() {
    throw new Error("getName() must be implemented");
  }

  async createSubaccount() {
    throw new Error("createSubaccount() must be implemented");
  }

  async initializeTransaction() {
    throw new Error("initializeTransaction() must be implemented");
  }

  async verifyTransaction() {
    throw new Error("verifyTransaction() must be implemented");
  }

  async refundTransaction() {
    throw new Error("refundTransaction() must be implemented");
  }

  verifyWebhookSignature() {
    throw new Error("verifyWebhookSignature() must be implemented");
  }

  parseWebhookEvent() {
    throw new Error("parseWebhookEvent() must be implemented");
  }
}

module.exports = PaymentProvider;
