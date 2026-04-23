const MockProvider = require("./providers/MockProvider");
const PaystackProvider = require("./providers/PaystackProvider");
const StitchProvider = require("./providers/StitchProvider");

const PROVIDERS = {
  mock: () => new MockProvider(),
  paystack: () => new PaystackProvider(),
  stitch: () => new StitchProvider(),
};

function getActiveProviderName() {
  const value = (process.env.PAYMENT_PROVIDER || "mock").toLowerCase().trim();
  return PROVIDERS[value] ? value : "mock";
}

function getPaymentProvider(providerName) {
  const name = (providerName || getActiveProviderName()).toLowerCase().trim();
  const factory = PROVIDERS[name];
  if (!factory) {
    throw new Error(`Unsupported payment provider: ${name}`);
  }
  return factory();
}

module.exports = {
  getActiveProviderName,
  getPaymentProvider,
};
