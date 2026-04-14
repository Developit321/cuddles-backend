/**
 * Migrates legacy Cloudinary profile image URLs on a single user to R2
 * (profileImages only; profileVerification.selfieUrl is untouched).
 *
 * R2: dotenv loads api/.env if present; any missing R2_* var falls back to the
 * same defaults as your deployed env (api/storage/r2.js still reads process.env).
 *
 * Usage (from api/):
 *   node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *   APPLY=1 node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *
 * Without APPLY=1: dry run (logs planned replacements, no R2/Mongo writes).
 *
 * Bulk dry run — South Africa this year (same filters as listUsersWithLegacyCloudinaryImages.js):
 *   DRY_RUN_SOUTH_AFRICA=1 node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *   YEAR=2026 COUNTRY="South Africa" DRY_RUN_SOUTH_AFRICA=1 node ...
 *   (Cannot be combined with APPLY=1 or APPLY_SOUTH_AFRICA=1.)
 *
 * Bulk dry run — Japan (no createdAt filter; all matching users):
 *   DRY_RUN_JAPAN=1 node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *   COUNTRY="..." DRY_RUN_JAPAN=1 node ...   (default location.country is 日本)
 *   (Cannot be combined with other geo dry runs, APPLY=1, APPLY_SOUTH_AFRICA, or APPLY_JAPAN.)
 *
 * Bulk dry run — United States (no createdAt; same shape as Japan):
 *   DRY_RUN_US=1 node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *   COUNTRY="United States" DRY_RUN_US=1 node ...   (default location.country is United States)
 *   (Cannot be combined with other geo dry runs, APPLY=1, or APPLY_US / other bulk apply flags.)
 *
 * Bulk apply — all matching users this year in South Africa (writes R2 + MongoDB):
 *   APPLY=1 APPLY_SOUTH_AFRICA=1 node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *   YEAR=2026 APPLY=1 APPLY_SOUTH_AFRICA=1 node ...
 *   Optional: MIGRATE_DELAY_MS=250 pause between users (default 250).
 *
 * Bulk apply — Japan (no createdAt; location.country default 日本; writes R2 + MongoDB):
 *   APPLY=1 APPLY_JAPAN=1 node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *   COUNTRY="..." APPLY=1 APPLY_JAPAN=1 node ...   (override country if needed)
 *
 * Bulk apply — United States (no createdAt; default United States; writes R2 + MongoDB):
 *   APPLY=1 APPLY_US=1 node scripts/migrateUserProfileImagesCloudinaryToR2.js
 *   COUNTRY="United States" APPLY=1 APPLY_US=1 node ...   (override if needed)
 *
 * Optional:
 *   USER_ID=<24hex>   (defaults to the test user below; ignored for bulk country modes)
 */

require("dotenv").config();

// Defaults match production R2 (used when env var not set, e.g. local CLI)
const R2_ENV_DEFAULTS = {
  R2_ACCOUNT_ID: "6428261e64f947a84efdf686909f6c4c",
  R2_ACCESS_KEY_ID: "10efa2dc93e40953130a9a2d1d5e3fa0",
  R2_SECRET_ACCESS_KEY:
    "7b048877a06c9ece1770f848a08652ca4f3d457edf6536426313b2195dde8ee9",
  R2_BUCKET: "cuddles-media-prod",
  R2_PUBLIC_BASE_URL: "https://media.invitable.uk",
};
for (const [key, value] of Object.entries(R2_ENV_DEFAULTS)) {
  if (!process.env[key]) process.env[key] = value;
}

const mongoose = require("mongoose");
const axios = require("axios");

const User = require("../models/User");
const {
  uploadImageBufferToR2,
  buildUserImageKey,
} = require("../storage/r2");
const {
  normalizeProfileImageFromBuffer,
} = require("../utils/normalizeProfileImage");

// Same values as api/index.js
const MONGODB_URI =
  "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/";
const CLOUDINARY_CLOUD_NAME = "dmqt8wnrd";

const LEGACY_REGEX_STRING = `^https://res\\.cloudinary\\.com/${CLOUDINARY_CLOUD_NAME}/image/upload`;
const LEGACY_URL_REGEX = new RegExp(LEGACY_REGEX_STRING);

const DEFAULT_TEST_USER_ID = "6975d111188f0d481a6bb894";

const DEFAULT_LOCATION_COUNTRY = "South Africa";
const DEFAULT_JAPAN_COUNTRY = "日本";
const DEFAULT_US_COUNTRY = "United States";

const APPLY =
  process.env.APPLY === "1" || process.env.APPLY === "true";

const DRY_RUN_SOUTH_AFRICA =
  process.env.DRY_RUN_SOUTH_AFRICA === "1" ||
  process.env.DRY_RUN_SOUTH_AFRICA === "true";

const APPLY_SOUTH_AFRICA =
  process.env.APPLY_SOUTH_AFRICA === "1" ||
  process.env.APPLY_SOUTH_AFRICA === "true";

const DRY_RUN_JAPAN =
  process.env.DRY_RUN_JAPAN === "1" || process.env.DRY_RUN_JAPAN === "true";

const APPLY_JAPAN =
  process.env.APPLY_JAPAN === "1" || process.env.APPLY_JAPAN === "true";

const DRY_RUN_US =
  process.env.DRY_RUN_US === "1" || process.env.DRY_RUN_US === "true";

const APPLY_US =
  process.env.APPLY_US === "1" || process.env.APPLY_US === "true";

function yearRange(year) {
  const y = Number(year);
  const start = new Date(y, 0, 1);
  const end = new Date(y + 1, 0, 1);
  return { start, end };
}

function getSouthAfricaMigrationContext() {
  const yearRaw = process.env.YEAR;
  const year = yearRaw ? parseInt(yearRaw, 10) : new Date().getFullYear();
  if (!Number.isFinite(year)) {
    throw new Error(`Invalid YEAR: ${yearRaw}`);
  }
  const locationCountry =
    process.env.COUNTRY != null && process.env.COUNTRY !== ""
      ? process.env.COUNTRY
      : DEFAULT_LOCATION_COUNTRY;
  const { start, end } = yearRange(year);
  const query = {
    createdAt: { $gte: start, $lt: end },
    "location.type": "Point",
    "location.country": locationCountry,
    profileImages: LEGACY_URL_REGEX,
  };
  return { year, locationCountry, query };
}

/** Japan dry run: no createdAt — matches location.country only (default: 日本). */
function getJapanMigrationContext() {
  const locationCountry =
    process.env.COUNTRY != null && process.env.COUNTRY !== ""
      ? process.env.COUNTRY
      : DEFAULT_JAPAN_COUNTRY;
  const query = {
    "location.type": "Point",
    "location.country": locationCountry,
    profileImages: LEGACY_URL_REGEX,
  };
  return { locationCountry, query };
}

/** United States dry run: no createdAt — matches location.country only (default: United States). */
function getUnitedStatesMigrationContext() {
  const locationCountry =
    process.env.COUNTRY != null && process.env.COUNTRY !== ""
      ? process.env.COUNTRY
      : DEFAULT_US_COUNTRY;
  const query = {
    "location.type": "Point",
    "location.country": locationCountry,
    profileImages: LEGACY_URL_REGEX,
  };
  return { locationCountry, query };
}

function isLegacyCloudinaryUrl(s) {
  return typeof s === "string" && LEGACY_URL_REGEX.test(s);
}

function legacyIndicesInProfileImages(profileImages) {
  const arr = profileImages || [];
  return arr
    .map((url, i) => (isLegacyCloudinaryUrl(url) ? i : -1))
    .filter((i) => i >= 0);
}

function _idStr(id) {
  return id && id.toString ? id.toString() : String(id);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchImageBuffer(url) {
  const res = await axios.get(url, {
    responseType: "arraybuffer",
    maxContentLength: 25 * 1024 * 1024,
    maxBodyLength: 25 * 1024 * 1024,
    timeout: 120000,
    validateStatus: (s) => s >= 200 && s < 300,
  });
  return Buffer.from(res.data);
}

async function uploadMigratedProfileImage({ sourceUrl, userId }) {
  const buffer = await fetchImageBuffer(sourceUrl);

  // Same max dimensions + WebP quality as image upload API (normalizeProfileImage)
  const normalized = await normalizeProfileImageFromBuffer(buffer);

  const key = buildUserImageKey({
    userId,
    mimetype: normalized.contentType,
    originalname: "migrated.webp",
    extOverride: normalized.extension,
  });

  return uploadImageBufferToR2({
    buffer: normalized.buffer,
    contentType: normalized.contentType,
    key,
  });
}

/**
 * Uploads + replaces legacy profileImages for one user. Throws on failure.
 */
async function migrateUserLegacyProfileImages(userDocId, profileImages) {
  const userIdStr = _idStr(userDocId);
  const indices = legacyIndicesInProfileImages(profileImages);
  if (indices.length === 0) {
    return { migrated: 0 };
  }

  const newProfileImages = [...(profileImages || [])];
  for (const i of indices) {
    const oldUrl = newProfileImages[i];
    const { url: newUrl } = await uploadMigratedProfileImage({
      sourceUrl: oldUrl,
      userId: userIdStr,
    });
    newProfileImages[i] = newUrl;
    console.error(`  [${i}]`);
    console.error(`    from: ${oldUrl}`);
    console.error(`    to:   ${newUrl}`);
  }

  await User.updateOne(
    { _id: userDocId },
    { $set: { profileImages: newProfileImages } },
  );

  return { migrated: indices.length };
}

async function runLegacyCountryBulkDryRun(titleLines, query) {
  for (const line of titleLines) {
    console.error(line);
  }
  console.error("(no R2 uploads, no MongoDB writes)\n");

  await mongoose.connect(MONGODB_URI);

  const users = await User.find(query)
    .select("_id name email createdAt profileImages")
    .sort({ createdAt: 1 })
    .lean();

  let totalLegacyUrls = 0;

  for (const user of users) {
    const profileImages = user.profileImages || [];
    const legacyIndices = legacyIndicesInProfileImages(profileImages);

    if (legacyIndices.length === 0) continue;

    console.error(`\n--- ${_idStr(user._id)} ${user.email || ""} (${user.name || "no name"}) ---`);
    for (const i of legacyIndices) {
      console.error(`  [${i}] from: ${profileImages[i]}`);
      console.error(`        to:   <R2 after bulk APPLY>`);
      totalLegacyUrls += 1;
    }
  }

  console.error(`\n--- summary ---`);
  console.error(`users: ${users.length}`);
  console.error(`legacyProfileImageUrls: ${totalLegacyUrls}`);
}

async function runSouthAfricaBulkDryRun() {
  let ctx;
  try {
    ctx = getSouthAfricaMigrationContext();
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }

  const { year, locationCountry, query } = ctx;

  await runLegacyCountryBulkDryRun(
    [
      `DRY RUN South Africa — createdAt in ${year}, location.country="${locationCountry}", legacy profileImages only`,
    ],
    query,
  );
}

async function runJapanBulkDryRun() {
  const { locationCountry, query } = getJapanMigrationContext();

  await runLegacyCountryBulkDryRun(
    [
      `DRY RUN Japan — location.country="${locationCountry}", no createdAt filter, legacy profileImages only`,
    ],
    query,
  );
}

async function runUnitedStatesBulkDryRun() {
  const { locationCountry, query } = getUnitedStatesMigrationContext();

  await runLegacyCountryBulkDryRun(
    [
      `DRY RUN United States — location.country="${locationCountry}", no createdAt filter, legacy profileImages only`,
    ],
    query,
  );
}

async function runBulkApplyForQuery(titleLines, query) {
  const delayMs = Math.max(
    0,
    parseInt(process.env.MIGRATE_DELAY_MS || "250", 10) || 0,
  );

  for (const line of titleLines) {
    console.error(line);
  }
  console.error("(uploading to R2 + updating MongoDB)\n");

  await mongoose.connect(MONGODB_URI);

  const users = await User.find(query)
    .select("_id name email profileImages")
    .sort({ createdAt: 1 })
    .lean();

  let usersOk = 0;
  let usersFailed = 0;
  let imagesMigrated = 0;

  for (let u = 0; u < users.length; u += 1) {
    const user = users[u];
    const profileImages = user.profileImages || [];
    const legacyIndices = legacyIndicesInProfileImages(profileImages);

    if (legacyIndices.length === 0) continue;

    console.error(
      `\n--- (${u + 1}/${users.length}) ${_idStr(user._id)} ${user.email || ""} ---`,
    );

    try {
      const { migrated } = await migrateUserLegacyProfileImages(
        user._id,
        profileImages,
      );
      imagesMigrated += migrated;
      usersOk += 1;
      console.error(`  OK — ${migrated} image(s) migrated.`);
    } catch (err) {
      usersFailed += 1;
      console.error(`  FAILED: ${err.message || err}`);
    }

    if (delayMs > 0 && u < users.length - 1) {
      await sleep(delayMs);
    }
  }

  console.error(`\n--- summary ---`);
  console.error(`users matched: ${users.length}`);
  console.error(`users migrated OK: ${usersOk}`);
  console.error(`users failed: ${usersFailed}`);
  console.error(`legacyProfileImageUrls migrated: ${imagesMigrated}`);
}

async function runSouthAfricaBulkApply() {
  let ctx;
  try {
    ctx = getSouthAfricaMigrationContext();
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }

  const { year, locationCountry, query } = ctx;

  await runBulkApplyForQuery(
    [
      `APPLY South Africa — createdAt in ${year}, location.country="${locationCountry}", legacy profileImages only`,
    ],
    query,
  );
}

async function runJapanBulkApply() {
  const { locationCountry, query } = getJapanMigrationContext();

  await runBulkApplyForQuery(
    [
      `APPLY Japan — location.country="${locationCountry}", no createdAt filter, legacy profileImages only`,
    ],
    query,
  );
}

async function runUnitedStatesBulkApply() {
  const { locationCountry, query } = getUnitedStatesMigrationContext();

  await runBulkApplyForQuery(
    [
      `APPLY United States — location.country="${locationCountry}", no createdAt filter, legacy profileImages only`,
    ],
    query,
  );
}

async function main() {
  if (DRY_RUN_SOUTH_AFRICA && APPLY_SOUTH_AFRICA) {
    console.error("Use only one of DRY_RUN_SOUTH_AFRICA or APPLY_SOUTH_AFRICA.");
    process.exit(1);
  }

  const dryGeoCount =
    (DRY_RUN_SOUTH_AFRICA ? 1 : 0) +
    (DRY_RUN_JAPAN ? 1 : 0) +
    (DRY_RUN_US ? 1 : 0);
  if (dryGeoCount > 1) {
    console.error(
      "Use only one of DRY_RUN_SOUTH_AFRICA, DRY_RUN_JAPAN, or DRY_RUN_US.",
    );
    process.exit(1);
  }

  if (DRY_RUN_US && APPLY_SOUTH_AFRICA) {
    console.error("DRY_RUN_US cannot be combined with APPLY_SOUTH_AFRICA.");
    process.exit(1);
  }

  if (DRY_RUN_US && APPLY_JAPAN) {
    console.error("DRY_RUN_US cannot be combined with APPLY_JAPAN.");
    process.exit(1);
  }

  if (DRY_RUN_US && APPLY_US) {
    console.error("Use only one of DRY_RUN_US or APPLY_US.");
    process.exit(1);
  }

  if (DRY_RUN_JAPAN && APPLY_US) {
    console.error("DRY_RUN_JAPAN cannot be combined with APPLY_US.");
    process.exit(1);
  }

  if (DRY_RUN_SOUTH_AFRICA && APPLY_US) {
    console.error("DRY_RUN_SOUTH_AFRICA cannot be combined with APPLY_US.");
    process.exit(1);
  }

  if (DRY_RUN_JAPAN && APPLY_SOUTH_AFRICA) {
    console.error("DRY_RUN_JAPAN cannot be combined with APPLY_SOUTH_AFRICA.");
    process.exit(1);
  }

  if (DRY_RUN_JAPAN && APPLY_JAPAN) {
    console.error("Use only one of DRY_RUN_JAPAN or APPLY_JAPAN.");
    process.exit(1);
  }

  if (APPLY_SOUTH_AFRICA && APPLY_JAPAN) {
    console.error("Use only one of APPLY_SOUTH_AFRICA or APPLY_JAPAN.");
    process.exit(1);
  }

  if (APPLY_SOUTH_AFRICA && APPLY_US) {
    console.error("Use only one of APPLY_SOUTH_AFRICA or APPLY_US.");
    process.exit(1);
  }

  if (APPLY_JAPAN && APPLY_US) {
    console.error("Use only one of APPLY_JAPAN or APPLY_US.");
    process.exit(1);
  }

  if (DRY_RUN_SOUTH_AFRICA) {
    if (APPLY) {
      console.error(
        "DRY_RUN_SOUTH_AFRICA is dry-run only; do not set APPLY=1.",
      );
      process.exit(1);
    }
    try {
      await runSouthAfricaBulkDryRun();
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      await mongoose.disconnect();
    }
    return;
  }

  if (DRY_RUN_JAPAN) {
    if (APPLY) {
      console.error("DRY_RUN_JAPAN is dry-run only; do not set APPLY=1.");
      process.exit(1);
    }
    try {
      await runJapanBulkDryRun();
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      await mongoose.disconnect();
    }
    return;
  }

  if (DRY_RUN_US) {
    if (APPLY) {
      console.error("DRY_RUN_US is dry-run only; do not set APPLY=1.");
      process.exit(1);
    }
    try {
      await runUnitedStatesBulkDryRun();
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      await mongoose.disconnect();
    }
    return;
  }

  if (APPLY_SOUTH_AFRICA) {
    if (!APPLY) {
      console.error(
        "APPLY_SOUTH_AFRICA requires APPLY=1 to confirm writes to R2 and MongoDB.",
      );
      process.exit(1);
    }
    try {
      await runSouthAfricaBulkApply();
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      await mongoose.disconnect();
    }
    return;
  }

  if (APPLY_JAPAN) {
    if (!APPLY) {
      console.error(
        "APPLY_JAPAN requires APPLY=1 to confirm writes to R2 and MongoDB.",
      );
      process.exit(1);
    }
    try {
      await runJapanBulkApply();
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      await mongoose.disconnect();
    }
    return;
  }

  if (APPLY_US) {
    if (!APPLY) {
      console.error(
        "APPLY_US requires APPLY=1 to confirm writes to R2 and MongoDB.",
      );
      process.exit(1);
    }
    try {
      await runUnitedStatesBulkApply();
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      await mongoose.disconnect();
    }
    return;
  }

  const userId =
    process.env.USER_ID && process.env.USER_ID.trim() !== ""
      ? process.env.USER_ID.trim()
      : DEFAULT_TEST_USER_ID;

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    console.error(`Invalid USER_ID: ${userId}`);
    process.exit(1);
  }

  console.error(`Target user: ${userId}`);
  console.error(`Mode: ${APPLY ? "APPLY (writes R2 + MongoDB)" : "DRY RUN (no writes)"}`);
  console.error("");

  try {
    await mongoose.connect(MONGODB_URI);

    const user = await User.findById(userId).lean();
    if (!user) {
      console.error("User not found.");
      process.exit(1);
    }

    const profileImages = user.profileImages || [];
    const legacyIndices = legacyIndicesInProfileImages(profileImages);

    if (legacyIndices.length === 0) {
      console.error("No legacy Cloudinary URLs in profileImages. Nothing to do.");
      return;
    }

    if (!APPLY) {
      for (const i of legacyIndices) {
        const oldUrl = profileImages[i];
        console.error(`[${i}]`);
        console.error(`  from: ${oldUrl}`);
        console.error(`  to:   <R2 URL after APPLY=1>`);
      }
      console.error("");
      console.error("Dry run only. Re-run with APPLY=1 to perform migration.");
      return;
    }

    await migrateUserLegacyProfileImages(user._id, profileImages);

    console.error("");
    console.error(`Updated profileImages (${legacyIndices.length} URL(s)).`);
  } catch (err) {
    console.error(err);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

main();
