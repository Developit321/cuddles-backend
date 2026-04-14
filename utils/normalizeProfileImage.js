const sharp = require("sharp");

const ALLOWED_INPUT_MIME_TYPES = new Set([
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",
]);

/** Same pipeline as POST /users/:userId/upload (max edge 1536, WebP q75). */
async function pipelineToProfileWebp(buffer) {
  return sharp(buffer, { failOn: "error" })
    .rotate()
    .resize({
      width: 1536,
      height: 1536,
      fit: "inside",
      withoutEnlargement: true,
    })
    .webp({ quality: 75 })
    .toBuffer();
}

async function normalizeProfileImageToJpeg(buffer, inputMimeType) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new Error("Invalid image buffer");
  }

  if (!ALLOWED_INPUT_MIME_TYPES.has(String(inputMimeType || "").toLowerCase())) {
    throw new Error("Unsupported image type");
  }

  const outBuffer = await pipelineToProfileWebp(buffer);

  return {
    buffer: outBuffer,
    contentType: "image/webp",
    extension: "webp",
  };
}

/**
 * Decode + resize like the upload API, without MIME checks (sharp infers format).
 * Use for migration / URLs where Content-Type may be wrong.
 */
async function normalizeProfileImageFromBuffer(buffer) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new Error("Invalid image buffer");
  }

  const outBuffer = await pipelineToProfileWebp(buffer);

  return {
    buffer: outBuffer,
    contentType: "image/webp",
    extension: "webp",
  };
}

module.exports = {
  normalizeProfileImageToJpeg,
  normalizeProfileImageFromBuffer,
  ALLOWED_INPUT_MIME_TYPES,
};

