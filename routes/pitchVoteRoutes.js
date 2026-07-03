// TEMP: pitch-vote — safe to delete after event
const crypto = require("crypto");
const express = require("express");
const multer = require("multer");
const mongoose = require("mongoose");
const PitchVotePitcher = require("../models/PitchVotePitcher");
const PitchVoteBallot = require("../models/PitchVoteBallot");
const PitchVoteVoter = require("../models/PitchVoteVoter");
const { uploadImageBufferToR2 } = require("../storage/r2");
const { normalizeProfileImageToJpeg } = require("../utils/normalizeProfileImage");

const router = express.Router();

const ALLOWED_INPUT_MIME_TYPES = new Set([
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",
]);

const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = ALLOWED_INPUT_MIME_TYPES.has(
      String(file?.mimetype || "").toLowerCase()
    );
    if (!ok) return cb(new Error("Only jpeg/png/webp images are allowed"));
    return cb(null, true);
  },
});

function handleUpload(fieldName) {
  return (req, res, next) => {
    imageUpload.single(fieldName)(req, res, (err) => {
      if (!err) return next();
      return res.status(400).json({ message: err.message || "Invalid upload" });
    });
  };
}

function optionalVoterPhotoUpload(req, res, next) {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  if (contentType.includes("application/json")) {
    return next();
  }
  return handleUpload("voterPhoto")(req, res, next);
}

function normalizePersonName(value) {
  return String(value || "").trim();
}

function isValidPersonName(name) {
  return name.length >= 1 && name.length <= 80;
}

function buildPitchVoteImageKey({ folder, mimetype, originalname, extOverride }) {
  const ext =
    extOverride ||
    (mimetype === "image/jpeg" || mimetype === "image/jpg"
      ? "jpg"
      : mimetype === "image/png"
        ? "png"
        : mimetype === "image/webp"
          ? "webp"
          : "jpg");
  const ts = Date.now();
  const rand = crypto.randomBytes(8).toString("hex");
  return `temp/pitch-vote/${folder}/${ts}-${rand}.${ext}`;
}

async function uploadPhoto(file, folder) {
  const normalized = await normalizeProfileImageToJpeg(
    file.buffer,
    file.mimetype
  );
  const key = buildPitchVoteImageKey({
    folder,
    mimetype: normalized.contentType,
    originalname: file.originalname,
    extOverride: normalized.extension,
  });
  const { url } = await uploadImageBufferToR2({
    buffer: normalized.buffer,
    contentType: normalized.contentType,
    key,
  });
  return url;
}

router.get("/pitchers", async (_req, res) => {
  try {
    const pitchers = await PitchVotePitcher.find()
      .sort({ name: 1, createdAt: 1 })
      .select("name photoUrl")
      .lean();

    return res.status(200).json({
      pitchers: pitchers.map((pitcher) => ({
        id: pitcher._id,
        name: pitcher.name,
        photoUrl: pitcher.photoUrl,
      })),
    });
  } catch (error) {
    console.error("[PitchVote] Failed to list pitchers:", error);
    return res.status(500).json({ message: "Could not load pitchers." });
  }
});

router.post("/pitchers", handleUpload("photo"), async (req, res) => {
  try {
    const name = normalizePersonName(req.body?.name);
    if (!isValidPersonName(name)) {
      return res
        .status(400)
        .json({ message: "Name is required (1-80 characters)." });
    }
    if (!req.file) {
      return res.status(400).json({ message: "Photo is required." });
    }

    const photoUrl = await uploadPhoto(req.file, "pitchers");
    const privateToken = crypto.randomUUID();

    const pitcher = await PitchVotePitcher.create({
      name,
      photoUrl,
      privateToken,
    });

    return res.status(201).json({
      id: pitcher._id,
      name: pitcher.name,
      photoUrl: pitcher.photoUrl,
      privateToken: pitcher.privateToken,
    });
  } catch (error) {
    console.error("[PitchVote] Failed to register pitcher:", error);
    return res.status(500).json({ message: "Could not register pitcher." });
  }
});

router.post("/voters", handleUpload("photo"), async (req, res) => {
  try {
    const name = normalizePersonName(req.body?.name);
    if (!isValidPersonName(name)) {
      return res
        .status(400)
        .json({ message: "Name is required (1-80 characters)." });
    }
    if (!req.file) {
      return res.status(400).json({ message: "Photo is required." });
    }

    const photoUrl = await uploadPhoto(req.file, "voters");

    const voter = await PitchVoteVoter.create({
      name,
      photoUrl,
    });

    return res.status(201).json({
      id: voter._id,
      name: voter.name,
      photoUrl: voter.photoUrl,
    });
  } catch (error) {
    console.error("[PitchVote] Failed to register voter:", error);
    return res.status(500).json({ message: "Could not register voter." });
  }
});

router.get("/pitchers/me", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) {
      return res.status(400).json({ message: "token is required." });
    }

    const pitcher = await PitchVotePitcher.findOne({ privateToken: token }).lean();
    if (!pitcher) {
      return res.status(404).json({ message: "Pitcher not found." });
    }

    const votes = await PitchVoteBallot.find({ pitcherId: pitcher._id })
      .sort({ createdAt: -1 })
      .select("voterName voterPhotoUrl createdAt")
      .lean();

    return res.status(200).json({
      pitcher: {
        id: pitcher._id,
        name: pitcher.name,
        photoUrl: pitcher.photoUrl,
      },
      votes: votes.map((vote) => ({
        voterName: vote.voterName,
        voterPhotoUrl: vote.voterPhotoUrl,
        createdAt: vote.createdAt,
      })),
    });
  } catch (error) {
    console.error("[PitchVote] Failed to load private pitcher view:", error);
    return res.status(500).json({ message: "Could not load your votes." });
  }
});

router.post("/pitchers/:id/vote", optionalVoterPhotoUpload, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(404).json({ message: "Pitcher not found." });
    }

    const pitcher = await PitchVotePitcher.findById(id).select("_id").lean();
    if (!pitcher) {
      return res.status(404).json({ message: "Pitcher not found." });
    }

    const voterId = String(req.body?.voterId || "").trim();
    let voterName;
    let voterPhotoUrl;

    if (voterId) {
      if (!mongoose.Types.ObjectId.isValid(voterId)) {
        return res.status(400).json({ message: "Invalid voter." });
      }

      const voter = await PitchVoteVoter.findById(voterId).lean();
      if (!voter) {
        return res.status(404).json({ message: "Voter not found." });
      }

      voterName = voter.name;
      voterPhotoUrl = voter.photoUrl;
    } else {
      voterName = normalizePersonName(req.body?.voterName);
      if (!isValidPersonName(voterName)) {
        return res
          .status(400)
          .json({ message: "Your name is required (1-80 characters)." });
      }
      if (!req.file) {
        return res.status(400).json({ message: "Your photo is required." });
      }

      voterPhotoUrl = await uploadPhoto(req.file, "voters");
    }

    await PitchVoteBallot.create({
      pitcherId: pitcher._id,
      voterName,
      voterPhotoUrl,
    });

    return res.status(201).json({ ok: true });
  } catch (error) {
    console.error("[PitchVote] Failed to record vote:", error);
    return res.status(500).json({ message: "Could not record vote." });
  }
});

module.exports = router;
