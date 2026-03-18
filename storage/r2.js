const crypto = require("crypto");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");

function requiredEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

function getPublicBaseUrl() {
  const base = requiredEnv("R2_PUBLIC_BASE_URL");
  return base.endsWith("/") ? base.slice(0, -1) : base;
}

function createR2Client() {
  const accountId = requiredEnv("R2_ACCOUNT_ID");
  return new S3Client({
    region: "auto",
    endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: requiredEnv("R2_ACCESS_KEY_ID"),
      secretAccessKey: requiredEnv("R2_SECRET_ACCESS_KEY"),
    },
    forcePathStyle: true,
  });
}

function randomHex(bytes = 12) {
  return crypto.randomBytes(bytes).toString("hex");
}

function guessExtension({ mimetype, originalname }) {
  if (mimetype === "image/jpeg") return "jpg";
  if (mimetype === "image/png") return "png";
  if (mimetype === "image/webp") return "webp";
  if (mimetype === "image/gif") return "gif";

  const m = (originalname || "").toLowerCase().match(/\.([a-z0-9]+)$/);
  if (!m) return "bin";
  return m[1];
}

async function uploadImageBufferToR2({ buffer, contentType, key }) {
  const Bucket = requiredEnv("R2_BUCKET");
  const client = createR2Client();

  await client.send(
    new PutObjectCommand({
      Bucket,
      Key: key,
      Body: buffer,
      ContentType: contentType || "application/octet-stream",
      ACL: "public-read",
    })
  );

  return {
    key,
    url: `${getPublicBaseUrl()}/${key}`,
  };
}

function buildUserImageKey({ userId, mimetype, originalname, extOverride }) {
  const ext = extOverride || guessExtension({ mimetype, originalname });
  const ts = Date.now();
  return `users/${userId}/${ts}-${randomHex(8)}.${ext}`;
}

module.exports = {
  uploadImageBufferToR2,
  buildUserImageKey,
};

