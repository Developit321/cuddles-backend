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

/** Yoco error bodies often use `description` instead of `message`. */
function formatYocoResponseError(data) {
  if (!data) return "";
  if (typeof data === "string") return data.trim();
  if (typeof data !== "object") return String(data);
  for (const key of ["message", "description", "title", "error"]) {
    const v = data[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  if (Array.isArray(data.errors)) {
    const parts = data.errors
      .map((e) =>
        typeof e === "string" ? e : e?.message || e?.description || e?.detail || ""
      )
      .filter(Boolean);
    if (parts.length) return parts.join("; ");
  }
  try {
    return JSON.stringify(data);
  } catch {
    return "";
  }
}

function formatYocoAxiosError(error) {
  const fromBody = formatYocoResponseError(error?.response?.data);
  if (fromBody) return fromBody;
  return String(error?.message || "").trim();
}

class YocoProvider extends PaymentProvider {
  getName() {
    return "yoco";
  }

  getBaseUrl() {
    return (process.env.YOCO_BASE_URL || "https://payments.yoco.com").trim();
  }

  getSecretKey() {
    const key = ensureConfig(process.env.YOCO_SECRET_KEY, "YOCO_SECRET_KEY");
    const mode = String(process.env.YOCO_API_MODE || "").trim().toLowerCase();
    if (mode === "test" && !key.startsWith("sk_test_")) {
      const err = new Error(
        "YOCO_API_MODE=test requires a Test secret key (sk_test_…). See https://developer.yoco.com/docs/checkout-api/authentication"
      );
      err.status = 500;
      throw err;
    }
    if (mode === "live" && !key.startsWith("sk_live_")) {
      const err = new Error(
        "YOCO_API_MODE=live requires a Live secret key (sk_live_…). See https://developer.yoco.com/docs/checkout-api/authentication"
      );
      err.status = 500;
      throw err;
    }
    return key;
  }

  getCheckoutPath() {
    return (process.env.YOCO_CHECKOUT_PATH || "/api/checkouts").trim();
  }

  getCheckoutByIdPathTemplate() {
    return (process.env.YOCO_CHECKOUT_BY_ID_PATH || "/api/checkouts/{id}").trim();
  }

  getRefundPathTemplate() {
    return (process.env.YOCO_REFUND_PATH || "/api/checkouts/{id}/refund").trim();
  }

  getWebhookHeaderName() {
    return (process.env.YOCO_WEBHOOK_HEADER || "x-yoco-signature").trim().toLowerCase();
  }

  mapPaymentStatus(raw) {
    const value = String(raw || "").toUpperCase();
    if (["SUCCESSFUL", "SUCCEEDED", "PAID", "SETTLED", "COMPLETED"].includes(value))
      return "paid";
    if (["FAILED", "CANCELLED", "EXPIRED"].includes(value)) return "failed";
    return "pending";
  }

  buildReference(payload = {}) {
    const source =
      payload.reference ||
      `YOCO-${payload.eventId || "event"}-${crypto.randomBytes(6).toString("hex")}`;
    return String(source).replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 64);
  }

  async createSubaccount(payload = {}) {
    // Yoco split-payout is handled in our backend payout ledger flow.
    const accountCode = `YOCO_HOST_${crypto
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
    const baseUrl = this.getBaseUrl();
    const path = this.getCheckoutPath();
    const merchantReference = this.buildReference(payload);

    // CreateCheckoutRequestBody: amount + currency required; processingMode is *response-only* and
    // follows the secret key (sk_test_ vs sk_live_), not anything in this payload.
    const body = {
      amount: Math.round(Number(payload.amount) || 0),
      currency: String(payload.currency || "ZAR").toUpperCase(),
      successUrl: payload.callbackUrl || undefined,
      cancelUrl: payload.callbackUrl || undefined,
      failureUrl: payload.callbackUrl || undefined,
      externalId: merchantReference,
      clientReferenceId: merchantReference,
      metadata: {
        eventId: payload.eventId || "",
        userId: payload.userId || "",
        merchantReference,
      },
    };
    const idempotencyKey =
      String(payload.idempotencyKey || "").trim() ||
      `yoco_init_${merchantReference}_${Date.now()}`;

    let data;
    try {
      const response = await axios.post(`${baseUrl}${path}`, body, {
        timeout: 15000,
        headers: {
          Authorization: `Bearer ${this.getSecretKey()}`,
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
        },
      });
      data = response?.data || {};
      const processingMode = data?.processingMode;
      console.log("[YocoProvider] checkout created", {
        checkoutId: data?.id,
        processingMode,
      });
      const envMode = String(process.env.YOCO_API_MODE || "").trim().toLowerCase();
      if (envMode === "live" && processingMode === "test") {
        console.warn(
          "[YocoProvider] Yoco returned processingMode=test while YOCO_API_MODE=live. " +
            "Live vs test is controlled only by the Checkout API secret (sk_live_ vs sk_test_); " +
            "it cannot be set in the JSON body. Restart the API after changing .env and confirm " +
            "the process loads YOCO_SECRET_KEY starting with sk_live_. " +
            "See https://developer.yoco.com/docs/checkout-api/authentication"
        );
      }
    } catch (error) {
      const detail =
        formatYocoAxiosError(error) ||
        `${error?.message || "Yoco initialize request failed"} (${error?.response?.status || error?.code || "unknown"}) at ${baseUrl}${path}`;
      const providerError = new Error(detail);
      providerError.status = error?.response?.status || 502;
      providerError.debug = {
        url: `${baseUrl}${path}`,
        status: error?.response?.status || null,
        code: error?.code || null,
        responseData: error?.response?.data || null,
      };
      throw providerError;
    }

    const checkoutId = data?.id || data?.checkoutId || merchantReference;
    const checkoutUrl = data?.redirectUrl || data?.url || data?.checkoutUrl || "";

    return {
      provider: this.getName(),
      reference: checkoutId,
      authorizationUrl: checkoutUrl,
      accessCode: "",
      status: this.mapPaymentStatus(data?.status),
      payload: {
        ...data,
        checkoutId,
        merchantReference,
        idempotencyKey,
      },
    };
  }

  async verifyTransaction(reference) {
    const baseUrl = this.getBaseUrl();
    const path = this.getCheckoutByIdPathTemplate().replace("{id}", encodeURIComponent(reference));
    let data;
    try {
      const response = await axios.get(`${baseUrl}${path}`, {
        timeout: 15000,
        headers: {
          Authorization: `Bearer ${this.getSecretKey()}`,
          "Content-Type": "application/json",
        },
      });
      data = response?.data || {};
    } catch (error) {
      const detail =
        formatYocoAxiosError(error) ||
        `Yoco verify failed (${error?.response?.status || "unknown"}) at ${baseUrl}${path}`;
      const providerError = new Error(detail);
      providerError.status = error?.response?.status || 502;
      throw providerError;
    }

    return {
      provider: this.getName(),
      reference: data?.id || reference,
      status: this.mapPaymentStatus(data?.status),
      paidAt: data?.paidAt ? new Date(data.paidAt) : null,
      payload: data,
    };
  }

  async refundTransaction(payload = {}) {
    const reference = String(payload.reference || "").trim();
    if (!reference) {
      const err = new Error("Yoco refund requires a payment reference");
      err.status = 400;
      throw err;
    }

    const amount = Math.round(Number(payload.amount) || 0);
    if (amount <= 0) {
      const err = new Error("Refund amount must be a positive number");
      err.status = 400;
      throw err;
    }

    const baseUrl = this.getBaseUrl();
    const path = this.getRefundPathTemplate().replace("{id}", encodeURIComponent(reference));
    const reasonText = String(payload.reason || "Event refund").slice(0, 500);
    const body = {
      amount,
      metadata: {
        reason: reasonText,
        ...(payload.eventId ? { eventId: String(payload.eventId) } : {}),
        ...(payload.userId ? { userId: String(payload.userId) } : {}),
      },
    };
    const idempotencyKey =
      String(payload.idempotencyKey || "").trim() ||
      `yoco_refund_${reference}_${amount}_${Date.now()}`;

    let data;
    try {
      const response = await axios.post(`${baseUrl}${path}`, body, {
        timeout: 15000,
        headers: {
          Authorization: `Bearer ${this.getSecretKey()}`,
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
        },
      });
      data = response?.data || {};
    } catch (error) {
      const detail =
        formatYocoAxiosError(error) ||
        `Yoco refund failed (${error?.response?.status || "unknown"}) at ${baseUrl}${path}`;
      const providerError = new Error(detail);
      providerError.status = error?.response?.status || 502;
      throw providerError;
    }

    return {
      provider: this.getName(),
      reference,
      status: "refunded",
      refundedAt: data?.refundedAt ? new Date(data.refundedAt) : new Date(),
      amount,
      payload: data,
    };
  }

  /**
   * Yoco Checkout API webhook signing:
   * https://developer.yoco.com/guides/online-payments/webhooks/verifying-the-events
   * Signed content: `${webhook-id}.${webhook-timestamp}.${rawBody}` with HMAC-SHA256 and base64 digest;
   * secret format `whsec_<base64>`; header `webhook-signature` entries look like `v1,<base64>`.
   */
  verifyWebhookSignature(rawBody, signature, secretKey, metadata = {}) {
    if (!rawBody || !signature || !secretKey) return false;
    const sig = String(signature).trim();
    const secret = String(secretKey).trim();

    const webhookId = String(metadata.webhookId || metadata["webhook-id"] || "").trim();
    const webhookTimestamp = String(
      metadata.webhookTimestamp || metadata["webhook-timestamp"] || ""
    ).trim();

    if (secret.startsWith("whsec_") && webhookId && webhookTimestamp) {
      const ts = Number(webhookTimestamp);
      if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 180) {
        return false;
      }
      let secretBytes;
      try {
        secretBytes = Buffer.from(secret.slice("whsec_".length), "base64");
      } catch {
        return false;
      }
      const signedContent = `${webhookId}.${webhookTimestamp}.${rawBody}`;
      let expected;
      try {
        expected = crypto.createHmac("sha256", secretBytes).update(signedContent).digest("base64");
      } catch {
        return false;
      }
      const candidates = [];
      const regex = /v1,([A-Za-z0-9+/=]+)/g;
      let match = regex.exec(sig);
      while (match) {
        candidates.push(match[1]);
        match = regex.exec(sig);
      }
      return candidates.some((candidate) => {
        try {
          const a = Buffer.from(candidate);
          const b = Buffer.from(expected);
          return a.length === b.length && crypto.timingSafeEqual(a, b);
        } catch {
          return false;
        }
      });
    }

    const computed = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
    return computed === sig;
  }

  parseWebhookEvent(rawBody) {
    const event = typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody || {};
    const payload = event.payload || event.data || {};
    return {
      eventType: event.type || event.event || "",
      reference:
        payload?.metadata?.merchantReference ||
        payload?.metadata?.externalId ||
        payload?.id ||
        payload?.paymentId ||
        event.paymentId ||
        event.reference ||
        "",
      status: payload?.status || event.status || "",
      payload: event,
    };
  }
}

module.exports = YocoProvider;
