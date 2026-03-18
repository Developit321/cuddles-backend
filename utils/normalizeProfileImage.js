const sharp = require("sharp");

const ALLOWED_INPUT_MIME_TYPES = new Set([
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",
]);

async function normalizeProfileImageToJpeg(buffer, inputMimeType) {
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new Error("Invalid image buffer");
  }

  if (!ALLOWED_INPUT_MIME_TYPES.has(String(inputMimeType || "").toLowerCase())) {
    throw new Error("Unsupported image type");
  }

  const outBuffer = await sharp(buffer, { failOn: "error" })
    .rotate()
    .resize({
      width: 1536,
      height: 1536,
      fit: "inside",
      withoutEnlargement: true,
    })
    .webp({ quality: 75 })
    .toBuffer();

  return {
    buffer: outBuffer,
    contentType: "image/webp",
    extension: "webp",
  };
}

module.exports = {
  normalizeProfileImageToJpeg,
  ALLOWED_INPUT_MIME_TYPES,
};

