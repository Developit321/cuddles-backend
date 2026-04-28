const crypto = require("crypto");

const ENC_PREFIX = "enc:v1:";
let warnedMissingKey = false;

function resolveKey() {
  const raw = String(process.env.HOST_PAYOUT_ENCRYPTION_KEY || "").trim();
  if (!raw) return null;

  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    return Buffer.from(raw, "hex");
  }

  try {
    const key = Buffer.from(raw, "base64");
    if (key.length === 32) return key;
  } catch {
    return null;
  }
  return null;
}

function getKeyOrWarn() {
  const key = resolveKey();
  if (!key && !warnedMissingKey) {
    warnedMissingKey = true;
    console.warn(
      "[fieldEncryption] HOST_PAYOUT_ENCRYPTION_KEY missing/invalid; storing payout fields as plaintext."
    );
  }
  return key;
}

function encryptText(value) {
  if (value == null) return "";
  const raw = String(value);
  if (!raw) return "";
  if (raw.startsWith(ENC_PREFIX)) return raw;

  const key = getKeyOrWarn();
  if (!key) return raw;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(raw, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = `${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
  return `${ENC_PREFIX}${payload}`;
}

function decryptText(value) {
  if (value == null) return "";
  const raw = String(value);
  if (!raw) return "";
  if (!raw.startsWith(ENC_PREFIX)) return raw;

  const key = getKeyOrWarn();
  if (!key) return raw;

  const body = raw.slice(ENC_PREFIX.length);
  const [ivB64, tagB64, dataB64] = body.split(":");
  if (!ivB64 || !tagB64 || !dataB64) return raw;

  try {
    const iv = Buffer.from(ivB64, "base64");
    const tag = Buffer.from(tagB64, "base64");
    const data = Buffer.from(dataB64, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    return raw;
  }
}

module.exports = {
  encryptText,
  decryptText,
  ENC_PREFIX,
};
