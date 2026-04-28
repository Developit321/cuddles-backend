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

function normalizeUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function parseBool(value, defaultValue = false) {
  if (value == null || value === "") return defaultValue;
  return ["1", "true", "yes", "y", "on"].includes(String(value).trim().toLowerCase());
}

function firstNonEmpty(values = []) {
  for (const value of values) {
    if (value == null) continue;
    const str = String(value).trim();
    if (str) return str;
  }
  return "";
}

function pickObjectStatus(payload = {}) {
  const candidates = [
    payload?.status,
    payload?.paymentStatus,
    payload?.transactionStatus,
    payload?.state,
    payload?.result,
    payload?.data?.status,
    payload?.data?.paymentStatus,
    payload?.attributes?.status,
    payload?.latestTransaction?.status,
  ];
  return firstNonEmpty(candidates);
}

function mapOzowStatus(raw) {
  const status = String(raw || "").trim().toLowerCase();
  if (!status) return "pending";
  if (
    [
      "complete",
      "completed",
      "paid",
      "successful",
      "succeeded",
      "settled",
      "success",
    ].includes(status)
  ) {
    return "paid";
  }
  if (["expired", "timeout", "timed_out"].includes(status)) return "expired";
  if (["cancelled", "canceled", "error", "failed", "declined"].includes(status)) return "failed";
  if (["created", "pending", "processing", "initiated"].includes(status)) return "pending";
  return "pending";
}

function computeLegacySha512Hash({ fields = [], secret = "" }) {
  const source = `${fields.join("")}${String(secret || "")}`.toLowerCase();
  return crypto.createHash("sha512").update(source).digest("hex");
}

class OzowProvider extends PaymentProvider {
  constructor() {
    super();
    this.cachedToken = null;
    this.cachedTokenExpiresAtMs = 0;
  }

  getName() {
    return "ozow";
  }

  getOneApiBaseUrl() {
    return normalizeUrl(process.env.OZOW_ONE_API_BASE_URL || "https://stagingone.ozow.com");
  }

  getOneApiTokenPath() {
    return String(process.env.OZOW_ONE_API_TOKEN_PATH || "/v1/token").trim();
  }

  getOneApiPaymentsPath() {
    return String(process.env.OZOW_ONE_API_PAYMENTS_PATH || "/v1/payments").trim();
  }

  getOneApiScope() {
    return String(process.env.OZOW_ONE_API_SCOPE || "payment").trim();
  }

  getTokenCacheSeconds() {
    const parsed = Number(process.env.OZOW_TOKEN_CACHE_SECONDS);
    if (!Number.isFinite(parsed) || parsed <= 0) return 3300;
    return Math.round(parsed);
  }

  getWebhookSignatureRequired() {
    return parseBool(process.env.OZOW_WEBHOOK_SIGNATURE_REQUIRED, false);
  }

  getLegacyPrivateKey() {
    return String(process.env.OZOW_PRIVATE_KEY || "").trim();
  }

  getLegacyWebhookFields() {
    const value = String(process.env.OZOW_WEBHOOK_HASH_FIELDS || "").trim();
    if (!value) {
      return [
        "SiteCode",
        "TransactionId",
        "TransactionReference",
        "Amount",
        "Status",
        "Optional1",
        "Optional2",
        "Optional3",
        "Optional4",
        "Optional5",
        "CurrencyCode",
        "IsTest",
        "StatusMessage",
      ];
    }
    return value
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
  }

  async getAccessToken(forceRefresh = false) {
    const now = Date.now();
    if (!forceRefresh && this.cachedToken && now < this.cachedTokenExpiresAtMs) {
      console.log("[OzowProvider] token cache hit", {
        baseUrl: this.getOneApiBaseUrl(),
        scope: this.getOneApiScope(),
        forceRefresh,
      });
      return this.cachedToken;
    }

    const tokenUrl = `${this.getOneApiBaseUrl()}${this.getOneApiTokenPath()}`;
    console.log("[OzowProvider] requesting token", {
      tokenUrl,
      scope: this.getOneApiScope(),
      hasClientId: Boolean(process.env.OZOW_CLIENT_ID),
      hasClientSecret: Boolean(process.env.OZOW_CLIENT_SECRET),
      forceRefresh,
    });
    const body = new URLSearchParams({
      client_id: ensureConfig(process.env.OZOW_CLIENT_ID, "OZOW_CLIENT_ID"),
      client_secret: ensureConfig(process.env.OZOW_CLIENT_SECRET, "OZOW_CLIENT_SECRET"),
      scope: this.getOneApiScope(),
      grant_type: "client_credentials",
    });

    let data;
    try {
      const response = await axios.post(tokenUrl, body.toString(), {
        timeout: 15000,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });
      data = response?.data || {};
      console.log("[OzowProvider] token response", {
        tokenUrl,
        hasAccessToken: Boolean(data?.access_token),
        tokenType: data?.token_type || "",
        expiresIn: data?.expires_in || "",
        scope: data?.scope || this.getOneApiScope(),
      });
    } catch (error) {
      const detail =
        error?.response?.data?.detail ||
        error?.response?.data?.message ||
        error?.response?.data?.title ||
        error?.message ||
        "Ozow token request failed";
      const providerError = new Error(detail);
      providerError.status = error?.response?.status || 502;
      console.error("[OzowProvider] token request failed", {
        tokenUrl,
        status: error?.response?.status || null,
        detail,
        responseData: error?.response?.data || null,
      });
      throw providerError;
    }

    const token = String(data?.access_token || "").trim();
    if (!token) {
      const err = new Error("Ozow token response missing access_token");
      err.status = 502;
      throw err;
    }

    const expiresIn = Math.max(60, Number(data?.expires_in) || this.getTokenCacheSeconds());
    const bufferSeconds = 60;
    this.cachedToken = token;
    this.cachedTokenExpiresAtMs = Date.now() + Math.max(1, expiresIn - bufferSeconds) * 1000;
    return token;
  }

  async ozowRequest({ method = "GET", path = "", body, params, retryOnUnauthorized = true } = {}) {
    const url = `${this.getOneApiBaseUrl()}${path}`;
    const redactedBody = body
      ? {
          ...body,
          // Avoid leaking sensitive values into logs.
          ...(body?.client_secret ? { client_secret: "***redacted***" } : {}),
        }
      : null;
    console.log("[OzowProvider] request start", {
      method,
      url,
      retryOnUnauthorized,
      params: params || null,
      body: redactedBody,
    });
    let token = await this.getAccessToken(false);

    const execute = async (accessToken) =>
      axios({
        method,
        url,
        timeout: 15000,
        data: body,
        params,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      });

    try {
      const response = await execute(token);
      console.log("[OzowProvider] request success", {
        method,
        url,
        status: response?.status || null,
      });
      return response?.data || {};
    } catch (error) {
      if (retryOnUnauthorized && error?.response?.status === 401) {
        console.warn("[OzowProvider] request unauthorized, refreshing token", {
          method,
          url,
        });
        token = await this.getAccessToken(true);
        try {
          const retried = await execute(token);
          console.log("[OzowProvider] request success after refresh", {
            method,
            url,
            status: retried?.status || null,
          });
          return retried?.data || {};
        } catch (retryError) {
          const detail =
            retryError?.response?.data?.detail ||
            retryError?.response?.data?.message ||
            retryError?.response?.data?.title ||
            retryError?.message ||
            "Ozow request failed";
          const providerError = new Error(detail);
          providerError.status = retryError?.response?.status || 502;
          console.error("[OzowProvider] request failed after token refresh", {
            method,
            url,
            status: retryError?.response?.status || null,
            detail,
            responseData: retryError?.response?.data || null,
          });
          throw providerError;
        }
      }

      const detail =
        error?.response?.data?.detail ||
        error?.response?.data?.message ||
        error?.response?.data?.title ||
        error?.message ||
        "Ozow request failed";
      const providerError = new Error(detail);
      providerError.status = error?.response?.status || 502;
      console.error("[OzowProvider] request failed", {
        method,
        url,
        status: error?.response?.status || null,
        detail,
        responseData: error?.response?.data || null,
      });
      throw providerError;
    }
  }

  buildMerchantReference(payload = {}) {
    const source =
      payload.reference ||
      payload.providerReference ||
      `OZOW-${payload.eventId || "event"}-${crypto.randomBytes(6).toString("hex")}`;
    return String(source).replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 64);
  }

  extractPaymentId(data = {}) {
    return firstNonEmpty([data?.id, data?.paymentId, data?.data?.id]);
  }

  extractPaymentStatus(data = {}) {
    const rootStatus = pickObjectStatus(data);
    if (rootStatus) return rootStatus;
    const latestTxStatus = pickObjectStatus(data?.latestTransaction || {});
    if (latestTxStatus) return latestTxStatus;
    const txList = Array.isArray(data?.transactions)
      ? data.transactions
      : Array.isArray(data?.data?.transactions)
      ? data.data.transactions
      : [];
    const txStatus = pickObjectStatus(txList[0] || {});
    return txStatus || "";
  }

  async fetchLatestTransaction(paymentData = {}) {
    const txLink = paymentData?.links?.transactions || paymentData?.data?.links?.transactions || "";
    if (!txLink) return null;
    const normalizedPath = String(txLink).startsWith("http")
      ? txLink.replace(this.getOneApiBaseUrl(), "")
      : txLink;
    if (!normalizedPath.startsWith("/")) return null;
    try {
      const txData = await this.ozowRequest({
        method: "GET",
        path: normalizedPath,
      });
      const items = Array.isArray(txData?.data)
        ? txData.data
        : Array.isArray(txData?.transactions)
        ? txData.transactions
        : Array.isArray(txData)
        ? txData
        : [];
      return items[0] || txData?.latestTransaction || null;
    } catch {
      return null;
    }
  }

  async createSubaccount(payload = {}) {
    // Phase 1: treat provider-side settlement account as approved in-app profile.
    const accountCode = `OZOW_HOST_${crypto
      .createHash("sha256")
      .update(String(payload.contactEmail || payload.businessName || Date.now()))
      .digest("hex")
      .slice(0, 16)}`;
    return {
      provider: this.getName(),
      accountCode,
      status: "active",
      payload: { ...payload, accountCode, mode: "platform_collected_settlement" },
    };
  }

  async initializeTransaction(payload = {}) {
    const amount = Math.max(0, Math.round(Number(payload.amount) || 0));
    if (amount <= 0) {
      const err = new Error("Ozow initialize requires a positive amount");
      err.status = 400;
      throw err;
    }

    const merchantReference = this.buildMerchantReference(payload);
    const requestBody = {
      siteCode: ensureConfig(process.env.OZOW_SITE_CODE, "OZOW_SITE_CODE"),
      amount: {
        currency: String(payload.currency || "ZAR").toUpperCase(),
        value: Number((amount / 100).toFixed(2)),
      },
      merchantReference,
      expireAt: payload.expiresAt || new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      returnUrl: payload.callbackUrl || undefined,
    };
    console.log("[OzowProvider] initialize transaction payload", {
      siteCode: requestBody.siteCode,
      amount: requestBody.amount,
      merchantReference,
      expireAt: requestBody.expireAt,
      hasReturnUrl: Boolean(requestBody.returnUrl),
      eventId: payload?.eventId || "",
      userId: payload?.userId || "",
    });

    const data = await this.ozowRequest({
      method: "POST",
      path: this.getOneApiPaymentsPath(),
      body: requestBody,
    });

    const paymentId = this.extractPaymentId(data) || merchantReference;
    const redirectUrl = firstNonEmpty([data?.redirectUrl, data?.links?.pay, data?.links?.redirect]);
    console.log("[OzowProvider] initialize transaction result", {
      paymentId,
      mappedStatus: mapOzowStatus(this.extractPaymentStatus(data)),
      hasRedirectUrl: Boolean(redirectUrl),
      rawStatus: this.extractPaymentStatus(data),
    });
    return {
      provider: this.getName(),
      reference: paymentId,
      authorizationUrl: redirectUrl,
      accessCode: "",
      status: mapOzowStatus(this.extractPaymentStatus(data)),
      payload: {
        ...data,
        paymentId,
        merchantReference,
        requestBody,
      },
    };
  }

  async verifyTransaction(reference) {
    const paymentId = String(reference || "").trim();
    if (!paymentId) {
      const err = new Error("Ozow verify requires a payment reference");
      err.status = 400;
      throw err;
    }

    const data = await this.ozowRequest({
      method: "GET",
      path: `${this.getOneApiPaymentsPath()}/${encodeURIComponent(paymentId)}`,
    });

    const latestTransaction = await this.fetchLatestTransaction(data);
    const rawStatus = firstNonEmpty([
      pickObjectStatus(latestTransaction || {}),
      this.extractPaymentStatus(data),
    ]);
    const paidAt = firstNonEmpty([
      latestTransaction?.paidAt,
      latestTransaction?.completedAt,
      latestTransaction?.createdAt,
      data?.paidAt,
      data?.completedAt,
    ]);
    console.log("[OzowProvider] verify transaction result", {
      paymentId,
      rawStatus,
      mappedStatus: mapOzowStatus(rawStatus),
      paidAt: paidAt || null,
      hasTransactionsLink: Boolean(data?.links?.transactions || data?.data?.links?.transactions),
    });

    return {
      provider: this.getName(),
      reference: this.extractPaymentId(data) || paymentId,
      status: mapOzowStatus(rawStatus),
      paidAt: paidAt ? new Date(paidAt) : null,
      payload: {
        ...data,
        latestTransaction: latestTransaction || null,
      },
    };
  }

  async refundTransaction() {
    const err = new Error("Ozow refunds are not wired in phase 1");
    err.status = 501;
    throw err;
  }

  verifyWebhookSignature(rawBody, _signature, _secretKey) {
    if (!this.getWebhookSignatureRequired()) {
      return true;
    }

    let payload = rawBody;
    if (typeof rawBody === "string") {
      try {
        payload = JSON.parse(rawBody);
      } catch {
        payload = {};
      }
    }
    const hashFromPayload = firstNonEmpty([payload?.Hash, payload?.hash]);
    if (!hashFromPayload) return false;

    const privateKey = this.getLegacyPrivateKey();
    if (!privateKey) return false;

    const hashFields = this.getLegacyWebhookFields();
    const fieldValues = hashFields.map((key) => firstNonEmpty([payload?.[key], payload?.[key?.toLowerCase()]]));
    const computed = computeLegacySha512Hash({ fields: fieldValues, secret: privateKey });
    return computed === String(hashFromPayload).trim().toLowerCase();
  }

  parseWebhookEvent(rawBody) {
    const event = typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody || {};
    const data = event?.data || event?.payment || event;
    const eventType = firstNonEmpty([event?.type, event?.eventType, event?.event, "payment_update"]);
    const reference = firstNonEmpty([
      data?.id,
      data?.paymentId,
      data?.payment?.id,
      data?.transactionId,
      data?.merchantReference,
      data?.transactionReference,
      event?.id,
      event?.reference,
    ]);
    const status = firstNonEmpty([
      data?.status,
      data?.paymentStatus,
      data?.transactionStatus,
      event?.status,
    ]);

    return {
      eventType,
      reference,
      status,
      payload: event,
    };
  }
}

module.exports = OzowProvider;
