/**
 * Read-only: prints how many matching users still have legacy Cloudinary URLs
 * in profileImages only (profileVerification.selfieUrl is ignored), and the
 * total count of those profile image URLs. Does not print per-user data.
 *
 * Usage (from api/):
 *   node scripts/listUsersWithLegacyCloudinaryImages.js
 *
 * Optional:
 *   YEAR=2026              (defaults to the calendar year when the script is run)
 *   COUNTRY=South Africa   (defaults to South Africa; must match location.country in DB)
 *
 * Mongo URI and Cloudinary cloud_name match api/index.js.
 * Does not upload to R2 or modify MongoDB.
 */

const mongoose = require("mongoose");
const User = require("../models/User");

// Same values as api/index.js (mongoose.connect + cloudinary.config)
const MONGODB_URI =
  "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/";
const CLOUDINARY_CLOUD_NAME = "dmqt8wnrd";

// Match User schema: location.type "Point" + location.country (GeoJSON + country string)
const DEFAULT_LOCATION_COUNTRY = "South Africa";

const LEGACY_REGEX_STRING = `^https://res\\.cloudinary\\.com/${CLOUDINARY_CLOUD_NAME}/image/upload`;
const LEGACY_URL_REGEX = new RegExp(LEGACY_REGEX_STRING);

function yearRange(year) {
  const y = Number(year);
  const start = new Date(y, 0, 1);
  const end = new Date(y + 1, 0, 1);
  return { start, end };
}

async function main() {
  const yearRaw = process.env.YEAR;
  const year = yearRaw ? parseInt(yearRaw, 10) : new Date().getFullYear();
  if (!Number.isFinite(year)) {
    console.error(`Invalid YEAR: ${yearRaw}`);
    process.exit(1);
  }

  const { start, end } = yearRange(year);
  const locationCountry =
    process.env.COUNTRY != null && process.env.COUNTRY !== ""
      ? process.env.COUNTRY
      : DEFAULT_LOCATION_COUNTRY;

  try {
    await mongoose.connect(MONGODB_URI);

    const query = {
      createdAt: { $gte: start, $lt: end },
      "location.type": "Point",
      "location.country": locationCountry,
      profileImages: LEGACY_URL_REGEX,
    };

    const pipeline = [
      { $match: query },
      {
        $addFields: {
          legacyProfileCount: {
            $size: {
              $filter: {
                input: { $ifNull: ["$profileImages", []] },
                as: "url",
                cond: {
                  $regexMatch: {
                    input: "$$url",
                    regex: LEGACY_REGEX_STRING,
                  },
                },
              },
            },
          },
        },
      },
      {
        $group: {
          _id: null,
          userCount: { $sum: 1 },
          legacyImageCount: { $sum: "$legacyProfileCount" },
        },
      },
    ];

    const [agg] = await User.aggregate(pipeline);
    const userCount = agg?.userCount ?? 0;
    const legacyImageCount = agg?.legacyImageCount ?? 0;

    console.log(`users: ${userCount}`);
    console.log(`legacyProfileImageUrls: ${legacyImageCount}`);
  } catch (err) {
    console.error(err);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

main();
