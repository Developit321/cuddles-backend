/**
 * Standalone pre-event murder mystery routes.
 * Host endpoints require ?key= matching PRE_EVENT_HOST_SECRET env var.
 */
const express = require("express");
const PreEventCharacter = require("../models/PreEventCharacter");
const PreEventSubmission = require("../models/PreEventSubmission");
const {
  DIETARY_PIZZA_OPTIONS,
  ROOM_PRESENCE_OPTIONS,
  ACTING_COMFORT_OPTIONS,
  DISCOMFORT_TOPIC_OPTIONS,
  DRINKS_PREFERENCE_OPTIONS,
} = require("../models/PreEventSubmission");
const PreEventSettings = require("../models/PreEventSettings");
const { ensurePreEventCharacters } = require("../services/preEventCharacterSeed");

const router = express.Router();

let charactersEnsured = false;

async function ensureCharactersOnce() {
  if (charactersEnsured) return;
  await ensurePreEventCharacters();
  charactersEnsured = true;
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function getOrCreateSettings() {
  let settings = await PreEventSettings.findOne();
  if (!settings) {
    settings = await PreEventSettings.create({ locked: false, lockedAt: null });
  }
  return settings;
}

function requireHostKey(req, res, next) {
  const secret = process.env.PRE_EVENT_HOST_SECRET;
  if (!secret) {
    return res
      .status(503)
      .json({ message: "Host access is not configured on the server." });
  }
  if (req.query.key !== secret) {
    return res.status(403).json({ message: "Invalid host key." });
  }
  return next();
}

function resolveDrinksPreference(submission) {
  if (submission.drinksPreference) {
    return submission.drinksPreference;
  }
  if (submission.drinksWine === false) {
    return "none";
  }
  return null;
}

function formatSubmission(submission, locked) {
  return {
    id: submission._id,
    email: submission.email,
    roomPresence: submission.roomPresence,
    actingComfort: submission.actingComfort,
    discomfortTopics: submission.discomfortTopics || [],
    discomfortOther: submission.discomfortOther || "",
    castingNotes: submission.castingNotes || "",
    dietaryPizza: submission.dietaryPizza || [],
    dietaryPizzaOther: submission.dietaryPizzaOther || "",
    drinksPreference: resolveDrinksPreference(submission),
    drinksWine: submission.drinksWine,
    submittedAt: submission.submittedAt,
    updatedAt: submission.updatedAt,
    locked,
  };
}

function validateDietaryPizza(dietaryPizza, dietaryPizzaOther) {
  if (!Array.isArray(dietaryPizza)) {
    return "dietaryPizza must be an array.";
  }

  const invalid = dietaryPizza.filter(
    (value) => !DIETARY_PIZZA_OPTIONS.includes(value),
  );
  if (invalid.length > 0) {
    return `Invalid dietary options: ${invalid.join(", ")}`;
  }

  if (dietaryPizza.includes("other")) {
    const otherText = String(dietaryPizzaOther || "").trim();
    if (!otherText) {
      return "dietaryPizzaOther is required when other is selected.";
    }
    if (otherText.length > 200) {
      return "dietaryPizzaOther must be 200 characters or fewer.";
    }
  }

  return null;
}

function validateDiscomfortTopics(discomfortTopics, discomfortOther) {
  if (!Array.isArray(discomfortTopics)) {
    return "discomfortTopics must be an array.";
  }

  const invalid = discomfortTopics.filter(
    (value) => !DISCOMFORT_TOPIC_OPTIONS.includes(value),
  );
  if (invalid.length > 0) {
    return `Invalid discomfort topics: ${invalid.join(", ")}`;
  }

  if (discomfortTopics.includes("other")) {
    const otherText = String(discomfortOther || "").trim();
    if (!otherText) {
      return "discomfortOther is required when other is selected.";
    }
    if (otherText.length > 200) {
      return "discomfortOther must be 200 characters or fewer.";
    }
  }

  return null;
}

router.use(async (_req, _res, next) => {
  try {
    await ensureCharactersOnce();
    next();
  } catch (error) {
    next(error);
  }
});

router.get("/characters", async (_req, res) => {
  try {
    const characters = await PreEventCharacter.find()
      .sort({ name: 1 })
      .select("name role teaser assignedUserId")
      .lean();

    return res.status(200).json({
      characters: characters.map((character) => ({
        id: character._id,
        name: character.name,
        role: character.role,
        teaser: character.teaser,
        assignedUserId: character.assignedUserId,
      })),
    });
  } catch (error) {
    console.error("[PreEvent] Failed to load characters:", error);
    return res.status(500).json({ message: "Could not load characters." });
  }
});

router.get("/settings", async (_req, res) => {
  try {
    const settings = await getOrCreateSettings();
    return res.status(200).json({ locked: settings.locked });
  } catch (error) {
    console.error("[PreEvent] Failed to load settings:", error);
    return res.status(500).json({ message: "Could not load settings." });
  }
});

router.get("/responses", requireHostKey, async (_req, res) => {
  try {
    const settings = await getOrCreateSettings();
    const submissions = await PreEventSubmission.find()
      .sort({ updatedAt: -1 })
      .lean();

    return res.status(200).json({
      locked: settings.locked,
      submissions: submissions.map((submission) => ({
        id: submission._id,
        email: submission.email,
        roomPresence: submission.roomPresence,
        actingComfort: submission.actingComfort,
        discomfortTopics: submission.discomfortTopics || [],
        discomfortOther: submission.discomfortOther || "",
        castingNotes: submission.castingNotes || "",
        dietaryPizza: submission.dietaryPizza || [],
        dietaryPizzaOther: submission.dietaryPizzaOther || "",
        drinksPreference: resolveDrinksPreference(submission),
        drinksWine: submission.drinksWine,
        submittedAt: submission.submittedAt,
        updatedAt: submission.updatedAt,
        locked: settings.locked,
      })),
    });
  } catch (error) {
    console.error("[PreEvent] Failed to load responses:", error);
    return res.status(500).json({ message: "Could not load responses." });
  }
});

router.post("/lock", requireHostKey, async (_req, res) => {
  try {
    const settings = await getOrCreateSettings();
    settings.locked = true;
    settings.lockedAt = new Date();
    await settings.save();
    return res.status(200).json({ locked: true, lockedAt: settings.lockedAt });
  } catch (error) {
    console.error("[PreEvent] Failed to lock submissions:", error);
    return res.status(500).json({ message: "Could not lock submissions." });
  }
});

router.post("/", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: "A valid email is required." });
    }

    const settings = await getOrCreateSettings();
    let submission = await PreEventSubmission.findOne({ email });

    if (!submission) {
      const now = new Date();
      submission = await PreEventSubmission.create({
        email,
        submittedAt: now,
        updatedAt: now,
      });
    }

    return res.status(200).json(formatSubmission(submission, settings.locked));
  } catch (error) {
    if (error?.code === 11000) {
      const email = normalizeEmail(req.body?.email);
      const submission = await PreEventSubmission.findOne({ email });
      const settings = await getOrCreateSettings();
      if (submission) {
        return res
          .status(200)
          .json(formatSubmission(submission, settings.locked));
      }
    }
    console.error("[PreEvent] Failed to create submission:", error);
    return res.status(500).json({ message: "Could not create submission." });
  }
});

router.get("/:email", async (req, res) => {
  try {
    const email = normalizeEmail(decodeURIComponent(req.params.email));
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: "A valid email is required." });
    }

    const submission = await PreEventSubmission.findOne({ email });
    if (!submission) {
      return res.status(404).json({ message: "Submission not found." });
    }

    const settings = await getOrCreateSettings();
    return res.status(200).json(formatSubmission(submission, settings.locked));
  } catch (error) {
    console.error("[PreEvent] Failed to fetch submission:", error);
    return res.status(500).json({ message: "Could not fetch submission." });
  }
});

router.patch("/:email", async (req, res) => {
  try {
    const email = normalizeEmail(decodeURIComponent(req.params.email));
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: "A valid email is required." });
    }

    const settings = await getOrCreateSettings();
    if (settings.locked) {
      return res.status(403).json({ message: "Submissions are closed." });
    }

    const submission = await PreEventSubmission.findOne({ email });
    if (!submission) {
      return res.status(404).json({ message: "Submission not found." });
    }

    const updates = {};
    const body = req.body || {};

    if (body.roomPresence !== undefined) {
      if (!ROOM_PRESENCE_OPTIONS.includes(body.roomPresence)) {
        return res.status(400).json({ message: "Invalid roomPresence value." });
      }
      updates.roomPresence = body.roomPresence;
    }

    if (body.actingComfort !== undefined) {
      if (!ACTING_COMFORT_OPTIONS.includes(body.actingComfort)) {
        return res
          .status(400)
          .json({ message: "Invalid actingComfort value." });
      }
      updates.actingComfort = body.actingComfort;
    }

    if (body.discomfortTopics !== undefined) {
      const discomfortError = validateDiscomfortTopics(
        body.discomfortTopics,
        body.discomfortOther ?? submission.discomfortOther,
      );
      if (discomfortError) {
        return res.status(400).json({ message: discomfortError });
      }
      updates.discomfortTopics = body.discomfortTopics;
    }

    if (body.discomfortOther !== undefined) {
      updates.discomfortOther = String(body.discomfortOther).trim();
    }

    if (body.castingNotes !== undefined) {
      const notes = String(body.castingNotes).trim();
      if (notes.length > 500) {
        return res
          .status(400)
          .json({ message: "castingNotes must be 500 characters or fewer." });
      }
      updates.castingNotes = notes;
    }

    if (body.dietaryPizza !== undefined) {
      const dietaryError = validateDietaryPizza(
        body.dietaryPizza,
        body.dietaryPizzaOther ?? submission.dietaryPizzaOther,
      );
      if (dietaryError) {
        return res.status(400).json({ message: dietaryError });
      }
      updates.dietaryPizza = body.dietaryPizza;
    }

    if (body.dietaryPizzaOther !== undefined) {
      updates.dietaryPizzaOther = String(body.dietaryPizzaOther).trim();
    }

    if (body.drinksPreference !== undefined) {
      if (!DRINKS_PREFERENCE_OPTIONS.includes(body.drinksPreference)) {
        return res.status(400).json({
          message: "drinksPreference must be none, red, or white.",
        });
      }
      updates.drinksPreference = body.drinksPreference;
      updates.drinksWine = body.drinksPreference !== "none";
    } else if (body.drinksWine !== undefined) {
      if (typeof body.drinksWine !== "boolean") {
        return res
          .status(400)
          .json({ message: "drinksWine must be true or false." });
      }
      updates.drinksWine = body.drinksWine;
      updates.drinksPreference = body.drinksWine ? null : "none";
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: "No valid fields to update." });
    }

    const mergedDiscomfort =
      updates.discomfortTopics ?? submission.discomfortTopics;
    const mergedDiscomfortOther =
      updates.discomfortOther ?? submission.discomfortOther;
    const discomfortError = validateDiscomfortTopics(
      mergedDiscomfort,
      mergedDiscomfortOther,
    );
    if (discomfortError) {
      return res.status(400).json({ message: discomfortError });
    }

    const mergedDietary = updates.dietaryPizza ?? submission.dietaryPizza;
    const mergedOther =
      updates.dietaryPizzaOther ?? submission.dietaryPizzaOther;
    const dietaryError = validateDietaryPizza(mergedDietary, mergedOther);
    if (dietaryError) {
      return res.status(400).json({ message: dietaryError });
    }

    Object.assign(submission, updates);
    submission.updatedAt = new Date();
    await submission.save();

    return res.status(200).json(formatSubmission(submission, settings.locked));
  } catch (error) {
    console.error("[PreEvent] Failed to update submission:", error);
    return res.status(500).json({ message: "Could not update submission." });
  }
});

module.exports = router;
