const axios = require("axios");
const crypto = require("crypto");
const PaymentProvider = require("./PaymentProvider");

function ensureConfig(value, keyName) {
  if (!value || !String(value).trim()) {
    const err = new Error(`Missing required configuration: ${keyName}`);
    err.status = 500;
    throw err;
  }
  return String(value).trim();
}

class StitchProvider extends PaymentProvider {
  getName() {
    return "stitch";
  }

  getBaseUrl() {
    return (process.env.STITCH_BASE_URL || "https://express.stitch.money").trim();
  }

  getClientSecret() {
    return ensureConfig(
      process.env.STITCH_CLIENT_SECRET || process.env.STITCH_API_KEY,
      "STITCH_CLIENT_SECRET (or STITCH_API_KEY fallback)"
    );
  }

  getClientId() {
    return ensureConfig(process.env.STITCH_CLIENT_ID, "STITCH_CLIENT_ID");
  }

  getTokenPath() {
    return (process.env.STITCH_TOKEN_PATH || "/api/v1/token").trim();
  }

  getPaymentLinksPath() {
    return (process.env.STITCH_PAYMENT_LINKS_PATH || "/api/v1/payment-links").trim();
  }

  getPaymentLinkByIdPathTemplate() {
    return (
      process.env.STITCH_PAYMENT_LINK_BY_ID_PATH || "/api/v1/payment-links/{id}"
    ).trim();
  }

  getPaymentByIdPathTemplate() {
    return (process.env.STITCH_PAYMENT_BY_ID_PATH || "/api/v1/payment/{id}").trim();
  }

  static tokenCache = {
    value: "",
    expiresAt: 0,
  };

  async getAccessToken() {
    const now = Date.now();
    if (StitchProvider.tokenCache.value && StitchProvider.tokenCache.expiresAt > now) {
      return StitchProvider.tokenCache.value;
    }

    const baseUrl = this.getBaseUrl();
    const tokenPath = this.getTokenPath();
    const response = await axios.post(
      `${baseUrl}${tokenPath}`,
      {
        clientId: this.getClientId(),
        clientSecret: this.getClientSecret(),
        scope: process.env.STITCH_SCOPE || "client_paymentrequest",
      },
      {
        timeout: 15000,
        headers: { "Content-Type": "application/json" },
      }
    );

    const token = response?.data?.data?.accessToken;
    if (!token) {
      const err = new Error("Stitch token exchange succeeded but no accessToken returned");
      err.status = 502;
      throw err;
    }

    // Stitch docs: token lifetime is 15 minutes. Cache slightly shorter.
    StitchProvider.tokenCache = {
      value: token,
      expiresAt: now + 14 * 60 * 1000,
    };
    return token;
  }

  async buildAuthHeaders() {
    const token = await this.getAccessToken();
    return {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    };
  }

  mapPaymentStatus(raw) {
    const value = String(raw || "").toUpperCase();
    if (value === "PAID" || value === "SETTLED") return "paid";
    if (value === "EXPIRED" || value === "CANCELLED") return "failed";
    return "pending";
  }

  buildMerchantReference(payload = {}) {
    const raw =
      payload.reference ||
      `EVT-${payload.eventId || "unknown"}-${crypto.randomBytes(6).toString("hex")}`;
    // Stitch docs: alphanumeric, spaces, hyphens only; <= 50 chars.
    return String(raw)
      .replace(/[^a-zA-Z0-9 -]/g, "-")
      .replace(/\s+/g, " ")
      .slice(0, 50)
      .trim();
  }

  buildPayerName(payload = {}) {
    const candidate = payload.name || payload.email || "Event attendee";
    return String(candidate).trim().slice(0, 40);
  }

  withRedirectUrl(checkoutUrl, callbackUrl) {
    if (!checkoutUrl || !callbackUrl) return checkoutUrl || "";
    try {
      const url = new URL(checkoutUrl);
      if (!url.searchParams.get("redirect_url")) {
        url.searchParams.set("redirect_url", callbackUrl);
      }
      return url.toString();
    } catch (_) {
      return checkoutUrl;
    }
  }

  async createSubaccount() {
    throw new Error("StitchProvider.createSubaccount is not implemented for MVP");
  }

  async initializeTransaction(payload = {}) {
    const baseUrl = this.getBaseUrl();

    const requestBody = {
      amount: payload.amount,
      merchantReference: this.buildMerchantReference(payload),
      payerName: this.buildPayerName(payload),
      payerEmailAddress: payload.email || undefined,
    };

    const path = this.getPaymentLinksPath();
    let data;
    try {
      const response = await axios.post(`${baseUrl}${path}`, requestBody, {
        timeout: 15000,
        headers: await this.buildAuthHeaders(),
      });
      data = response?.data?.data?.payment || response?.data?.data || response?.data || {};
    } catch (error) {
      const fieldErrors = error?.response?.data?.fieldErrors;
      const generalErrors = error?.response?.data?.generalErrors;
      const detail =
        (Array.isArray(generalErrors) && generalErrors.length
          ? generalErrors.join(", ")
          : "") ||
        (fieldErrors ? JSON.stringify(fieldErrors) : "");
      const providerError = new Error(
        detail ||
          error?.response?.data?.message ||
          `Stitch initialize failed (${error?.response?.status || "unknown"}) at ${baseUrl}${path}`
      );
      providerError.status = error?.response?.status || 502;
      throw providerError;
    }

    const checkoutUrl = this.withRedirectUrl(
      data.link || data.url || "",
      payload.callbackUrl || ""
    );

    return {
      provider: this.getName(),
      reference: data.id || requestBody.merchantReference,
      authorizationUrl: checkoutUrl,
      accessCode: "",
      status: this.mapPaymentStatus(data.status),
      payload: data,
    };
  }

  async verifyTransaction(reference) {
    const baseUrl = this.getBaseUrl();
    const path = this.getPaymentLinkByIdPathTemplate().replace(
      "{id}",
      encodeURIComponent(reference)
    );

    let data;
    try {
      const response = await axios.get(`${baseUrl}${path}`, {
        timeout: 15000,
        headers: await this.buildAuthHeaders(),
      });
      data = response?.data?.data?.payment || response?.data?.data || response?.data || {};
    } catch (error) {
      // Some integrations may return the primary payment under /payment/{id}
      const altPath = this.getPaymentByIdPathTemplate().replace(
        "{id}",
        encodeURIComponent(reference)
      );
      try {
        const altResponse = await axios.get(`${baseUrl}${altPath}`, {
          timeout: 15000,
          headers: await this.buildAuthHeaders(),
        });
        data =
          altResponse?.data?.data?.payment ||
          altResponse?.data?.data ||
          altResponse?.data ||
          {};
      } catch (altError) {
        const providerError = new Error(
          altError?.response?.data?.message ||
            `Stitch verify failed (${altError?.response?.status || error?.response?.status || "unknown"}) at ${baseUrl}${path}`
        );
        providerError.status = altError?.response?.status || error?.response?.status || 502;
        throw providerError;
      }
    }

    return {
      provider: this.getName(),
      reference: data.id || reference,
      status: this.mapPaymentStatus(data.status),
      paidAt: data.paidAt ? new Date(data.paidAt) : null,
      payload: data,
    };
  }

  verifyWebhookSignature(rawBody, signature, secretKey) {
    if (!signature || !secretKey || !rawBody) return false;
    const computed = crypto
      .createHmac("sha256", secretKey)
      .update(rawBody)
      .digest("hex");
    return computed === signature;
  }

  parseWebhookEvent(rawBody) {
    const event = typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody || {};
    return {
      eventType: event.eventType || event.type || "",
      reference: event.reference || event.data?.reference || "",
      status: event.status || event.data?.status || "",
      payload: event,
    };
  }
}

module.exports = StitchProvider;
