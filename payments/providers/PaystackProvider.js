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

function formatPaystackResponseError(data) {
  if (!data) return "";
  if (typeof data === "string") return data.trim();
  if (typeof data !== "object") return String(data);
  const msg = data.message;
  if (typeof msg === "string" && msg.trim()) return msg.trim();
  try {
    return JSON.stringify(data);
  } catch {
    return "";
  }
}

function formatPaystackAxiosError(error) {
  const fromBody = formatPaystackResponseError(error?.response?.data);
  if (fromBody) return fromBody;
  return String(error?.message || "").trim();
}

class PaystackProvider extends PaymentProvider {
  getName() {
    return "paystack";
  }

  getBaseUrl() {
    return (process.env.PAYSTACK_BASE_URL || "https://api.paystack.co").trim();
  }

  getSecretKey() {
    return ensureConfig(process.env.PAYSTACK_SECRET_KEY, "PAYSTACK_SECRET_KEY");
  }

  /** HTTPS page that redirects into the app deep link (same idea as Stitch bridge). */
  getRedirectBridgeUrl() {
    return (
      process.env.PAYSTACK_CALLBACK_BRIDGE_URL ||
      process.env.PAYMENT_CALLBACK_BRIDGE_URL ||
      process.env.STITCH_REDIRECT_BRIDGE_URL ||
      ""
    )
      .trim();
  }

  normalizeCallbackUrl(callbackUrl) {
    if (!callbackUrl) return "";
    if (/^https?:\/\//i.test(callbackUrl)) return callbackUrl;

    const bridge = this.getRedirectBridgeUrl();
    if (!bridge) return "";
    try {
      const bridgeUrl = new URL(bridge);
      bridgeUrl.searchParams.set("deep_link", callbackUrl);
      return bridgeUrl.toString();
    } catch (_) {
      return "";
    }
  }

  /**
   * Percentage of each charge that goes to the main (platform) Paystack account;
   * remainder goes to the subaccount. See Paystack Create Subaccount docs.
   */
  getSubaccountPlatformPercent() {
    const raw = process.env.PAYSTACK_SUBACCOUNT_PLATFORM_PERCENT;
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 0 && n <= 100) return n;
    return 10;
  }

  buildTransactionReference(payload = {}) {
    const suffix = crypto.randomBytes(10).toString("hex");
    const base = `evt_${payload.eventId || "e"}_${payload.userId || "u"}_${suffix}`;
    return String(base)
      .replace(/[^a-zA-Z0-9_-]/g, "-")
      .slice(0, 100);
  }

  mapPaymentStatus(raw) {
    const value = String(raw || "").toLowerCase();
    if (value === "success") return "success";
    if (value === "failed" || value === "reversed") return "failed";
    if (value === "abandoned") return "failed";
    return "pending";
  }

  /**
   * Paystack List Banks only accepts: ghana, kenya, nigeria, south africa (see Miscellaneous API).
   * Map common shortcuts (za, ng) to those strings.
   */
  normalizeBankListCountry(country) {
    const raw = String(country || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, " ");
    const aliases = {
      za: "south africa",
      zaf: "south africa",
      rsa: "south africa",
      ng: "nigeria",
      ngn: "nigeria",
      gh: "ghana",
      ghs: "ghana",
      ke: "kenya",
      kes: "kenya",
    };
    if (aliases[raw]) return aliases[raw];
    if (raw === "south africa" || raw.includes("south africa")) return "south africa";
    if (raw === "nigeria" || raw === "ngn") return "nigeria";
    if (raw === "ghana") return "ghana";
    if (raw === "kenya") return "kenya";
    return raw.replace(/[^a-z ]/g, "").trim() || "south africa";
  }

  /**
   * Settlement bank codes for subaccounts — use `code` from each item (Paystack docs: List Banks).
   * @param {string} country Paystack country slug (e.g. south africa) or alias za, ng, gh, ke
   */
  async listBanks(country = "south africa") {
    const c = this.normalizeBankListCountry(country);
    const baseUrl = this.getBaseUrl();
    try {
      const response = await axios.get(`${baseUrl}/bank`, {
        timeout: 20000,
        headers: {
          Authorization: `Bearer ${this.getSecretKey()}`,
        },
        params: { country: c, perPage: 100 },
      });
      const data = response?.data?.data;
      return Array.isArray(data) ? data : [];
    } catch (error) {
      const detail =
        formatPaystackAxiosError(error) ||
        `Paystack list banks failed (${error?.response?.status || error?.code || "unknown"})`;
      const providerError = new Error(detail);
      providerError.status = error?.response?.status || 502;
      throw providerError;
    }
  }

  async paystackRequest({ method, path, data }) {
    const baseUrl = this.getBaseUrl();
    const url = `${baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    try {
      const response = await axios({
        method,
        url,
        timeout: 20000,
        headers: {
          Authorization: `Bearer ${this.getSecretKey()}`,
          "Content-Type": "application/json",
        },
        ...(data != null ? { data } : {}),
      });
      return response?.data ?? {};
    } catch (error) {
      const detail =
        formatPaystackAxiosError(error) ||
        `Paystack request failed (${error?.response?.status || error?.code || "unknown"}) at ${url}`;
      const providerError = new Error(detail);
      providerError.status = error?.response?.status || 502;
      providerError.debug = {
        url,
        status: error?.response?.status || null,
        code: error?.code || null,
        responseData: error?.response?.data || null,
      };
      throw providerError;
    }
  }

  async createSubaccount(payload = {}) {
    const businessName = String(payload.businessName || "").trim();
    const settlementBank = String(payload.settlementBankCode || "").trim();
    const accountNumber = String(payload.accountNumber || "").replace(/\s/g, "").trim();

    if (!businessName || !settlementBank || !accountNumber) {
      const err = new Error(
        "Paystack subaccount requires businessName, settlementBankCode, and accountNumber"
      );
      err.status = 400;
      throw err;
    }

    const body = {
      business_name: businessName.slice(0, 255),
      settlement_bank: settlementBank,
      account_number: accountNumber,
      percentage_charge: this.getSubaccountPlatformPercent(),
      description: `Host: ${businessName}`.slice(0, 500),
      primary_contact_email: String(payload.contactEmail || "").trim() || undefined,
      primary_contact_name: String(payload.contactName || "").trim() || undefined,
      primary_contact_phone: String(payload.contactPhone || "").replace(/\s/g, "").trim() || undefined,
    };

    const meta = {
      entity_type: String(payload.entityType || payload.payoutEntityType || "individual"),
      platform: "cuddles",
    };
    if (payload.userId) meta.host_user_id = String(payload.userId).slice(0, 32);
    const companyReg = String(
      payload.companyRegistrationNumber || payload.companyRegNumber || ""
    ).trim();
    if (companyReg) meta.company_registration = companyReg.slice(0, 60);
    body.metadata = JSON.stringify(meta);

    const res = await this.paystackRequest({ method: "POST", path: "/subaccount", data: body });
    if (!res?.status || !res?.data?.subaccount_code) {
      const err = new Error(res?.message || "Paystack did not return a subaccount code");
      err.status = 502;
      throw err;
    }

    const code = res.data.subaccount_code;
    const active = res.data.active === true || res.data.active === 1;
    return {
      provider: this.getName(),
      accountCode: code,
      status: active ? "active" : "action_required",
      payload: res.data,
    };
  }

  async initializeTransaction(payload = {}) {
    const amount = Math.max(0, Math.round(Number(payload.amount) || 0));
    if (amount <= 0) {
      const err = new Error("Paystack initialize requires a positive amount");
      err.status = 400;
      throw err;
    }

    const email = String(payload.email || "").trim();
    if (!email) {
      const err = new Error("Paystack initialize requires customer email");
      err.status = 400;
      throw err;
    }

    const reference = this.buildTransactionReference(payload);
    const currency = String(payload.currency || "NGN").toUpperCase();
    const rawCallback = String(payload.callbackUrl || "").trim();
    const callbackUrl = this.normalizeCallbackUrl(rawCallback) || rawCallback;

    const body = {
      email,
      amount,
      currency,
      reference,
      metadata: {
        event_id: String(payload.eventId || ""),
        user_id: String(payload.userId || ""),
      },
    };

    if (callbackUrl) {
      body.callback_url = callbackUrl;
    }

    const sub = String(payload.subaccountCode || "").trim();
    const skipSub =
      String(process.env.PAYSTACK_SKIP_SUBACCOUNT || "")
        .trim()
        .toLowerCase() === "1" ||
      ["true", "yes"].includes(String(process.env.PAYSTACK_SKIP_SUBACCOUNT || "").trim().toLowerCase());
    const looksLikePaystackSubaccount = /^ACCT_[A-Za-z0-9_]+$/.test(sub);
    if (sub && !skipSub && looksLikePaystackSubaccount) {
      body.subaccount = sub;
    } else if (sub && !skipSub && !looksLikePaystackSubaccount) {
      console.warn("[PaystackProvider] omitting invalid subaccount for initialize (not a Paystack ACCT_ code)", {
        eventId: payload.eventId || "",
        hint: "Host profile may still hold a code from another provider; approve Paystack payout or set PAYSTACK_SKIP_SUBACCOUNT=1",
      });
    }

    const res = await this.paystackRequest({ method: "POST", path: "/transaction/initialize", data: body });
    if (!res?.status || !res?.data?.authorization_url) {
      const err = new Error(res?.message || "Paystack did not return an authorization URL");
      err.status = 502;
      throw err;
    }

    const data = res.data;
    return {
      provider: this.getName(),
      reference: data.reference || reference,
      authorizationUrl: data.authorization_url || "",
      accessCode: data.access_code || "",
      status: "pending",
      payload: {
        ...data,
        paystackReference: data.reference || reference,
        callbackUrlUsed: callbackUrl || "",
      },
    };
  }

  async verifyTransaction(reference) {
    const ref = encodeURIComponent(String(reference || "").trim());
    if (!ref) {
      const err = new Error("Paystack verify requires a reference");
      err.status = 400;
      throw err;
    }

    const res = await this.paystackRequest({
      method: "GET",
      path: `/transaction/verify/${ref}`,
    });

    if (!res?.data) {
      const err = new Error(res?.message || "Paystack verify returned no transaction data");
      err.status = 502;
      throw err;
    }

    const data = res.data;
    const mapped = this.mapPaymentStatus(data.status);

    let paidAt = null;
    if (data.paid_at != null && data.paid_at !== "") {
      if (typeof data.paid_at === "number" && Number.isFinite(data.paid_at)) {
        const ms = data.paid_at < 1e12 ? data.paid_at * 1000 : data.paid_at;
        const d = new Date(ms);
        if (!Number.isNaN(d.getTime())) paidAt = d;
      } else {
        const d = new Date(data.paid_at);
        if (!Number.isNaN(d.getTime())) paidAt = d;
      }
    }

    return {
      provider: this.getName(),
      reference: data.reference || reference,
      status: mapped === "success" ? "success" : mapped,
      paidAt,
      payload: data,
    };
  }

  async refundTransaction(payload = {}) {
    const reference = String(payload.reference || "").trim();
    if (!reference) {
      const err = new Error("Paystack refund requires a payment reference");
      err.status = 400;
      throw err;
    }

    const amount = Math.round(Number(payload.amount) || 0);
    if (amount <= 0) {
      const err = new Error("Refund amount must be a positive number");
      err.status = 400;
      throw err;
    }

    const providerTx = payload.providerTransactionId ?? payload.paystackTransactionId;
    const txForPaystack =
      providerTx != null && String(providerTx).trim() !== ""
        ? String(providerTx).trim()
        : reference;

    const body = {
      transaction: txForPaystack,
      amount,
      merchant_note: String(payload.reason || "Event refund").slice(0, 500),
    };

    const res = await this.paystackRequest({ method: "POST", path: "/refund", data: body });
    if (!res?.status) {
      const err = new Error(res?.message || "Paystack refund failed");
      err.status = 502;
      throw err;
    }

    const data = res.data || {};
    return {
      provider: this.getName(),
      reference,
      status: "refunded",
      refundedAt: data?.createdAt ? new Date(data.createdAt) : new Date(),
      amount,
      payload: data,
    };
  }

  verifyWebhookSignature(rawBody, signature, secretKey) {
    if (!signature || !secretKey) return false;
    const body =
      typeof rawBody === "string"
        ? rawBody
        : Buffer.isBuffer(rawBody)
          ? rawBody.toString("utf8")
          : rawBody != null
            ? JSON.stringify(rawBody)
            : "";
    if (!body) return false;
    const hash = crypto.createHmac("sha512", secretKey).update(body).digest("hex");
    const sig = String(signature).trim();
    if (hash.length !== sig.length) return false;
    try {
      return crypto.timingSafeEqual(Buffer.from(hash, "utf8"), Buffer.from(sig, "utf8"));
    } catch {
      return false;
    }
  }

  parseWebhookEvent(rawBody) {
    const event = typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody || {};
    const data = event.data || {};
    const eventType = event.event || "";

    let reference =
      data.reference ||
      data.transaction?.reference ||
      data.trans?.reference ||
      "";
    if (!reference && typeof data.authorization === "object" && data.authorization?.reference) {
      reference = data.authorization.reference;
    }

    let status = data.status || "";
    if (eventType === "charge.success") {
      status = status || data.status || "success";
    } else if (eventType === "charge.failed") {
      status = "failed";
    }

    return {
      eventType,
      reference: String(reference || ""),
      status: String(status || ""),
      payload: event,
    };
  }
}

module.exports = PaystackProvider;
