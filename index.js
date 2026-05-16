require("dotenv").config();

const bodyParser = require("body-parser");
const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");
const cron = require("node-cron");
const User = require("./models/User");
const Report = require("./models/Report");
const SharedQuestion = require("./models/SharedQuestion");
const Question = require("./models/ Question");
const Message = require("./models/message");
const Event = require("./models/Event");
const EventPayment = require("./models/EventPayment");
const {
  countOccupiedSeats,
  computeNextEventStatus,
  expirePendingPaidAdmissions,
} = require("./services/eventSeatHold");
const HostPayoutProfile = require("./models/HostPayoutProfile");
const EventMessage = require("./models/EventMessage");
const Notification = require("./models/Notification");
const Rating = require("./models/Rating");
const SuperFlirt = require("./models/SuperFlirt");
const Boost = require("./models/Boost");
const MissionStats = require("./models/MissionStats");
const jwt = require("jsonwebtoken");
const cloudinary = require("cloudinary");
const app = express();
const port = 3000;
const multer = require("multer");
const { resolve } = require("path");
const Chat = require("./models/message");
const http = require("http").createServer(app);
const io = require("socket.io")(http); // Pass the HTTP server instance
const bcrypt = require("bcryptjs");
const {
  sendNotification,
  sendNotificationBatch,
} = require("./notifications/pushNotifications");
const {
  getQueue,
  enqueueNearbyEvent,
  enqueueNearby60Fill,
  enqueueCapetownWeekend,
  enqueueCampaign,
} = require("./queues/nearbyNotifications");
const notificationStrings = require("./notifications/notificationStrings");
const {
  uploadImageBufferToR2,
  buildUserImageKey,
  buildEventImageKey,
  deleteObjectFromR2,
  keyFromPublicUrl,
} = require("./storage/r2");
const {
  normalizeProfileImageToJpeg,
  ALLOWED_INPUT_MIME_TYPES,
} = require("./utils/normalizeProfileImage");
const {
  validateCapacity,
  getCapacityLimits,
  FREE_EVENT_MAX_CAPACITY,
} = require("./utils/eventCapacity");
const {
  shouldSendNotification,
  getCategoryForType,
  getRecentlyNotifiedUserIds,
  DISCOVERY_COOLDOWN_MS,
} = require("./notifications/notificationCaps");
const { ObjectId } = require("mongodb");
const { updateUserCountry } = require("./Controllers/userController");
const RegionalCampaign = require("./models/RegionalCampaign");
const {
  executeCampaign,
  buildGeoQuery,
} = require("./campaigns/executeCampaign");

// Returns the notification strings for the given language, falling back to English
const getStrings = (lang) =>
  notificationStrings[lang] || notificationStrings["en"];

// Replaces {token} placeholders in a string with values from a params object
const interpolate = (str, params = {}) =>
  Object.entries(params).reduce(
    (s, [k, v]) => s.replace(new RegExp(`\\{${k}\\}`, "g"), v),
    str,
  );

// Map to store user socket connections
const userSockets = new Map();

const userRoutes = require("./routes/userRoutes");
const createPaymentRoutes = require("./routes/paymentRoutes");
const ticketRoutes = require("./routes/ticketRoutes");
const {
  createRefund,
  markEventPayoutsEligible,
} = require("./services/paymentService");
const MISSION_STATS_SINGLETON_KEY = "global";
const DEFAULT_MISSION_GOAL =
  Number(process.env.MISSION_GOAL) > 0
    ? Number(process.env.MISSION_GOAL)
    : 1000000;

const ensureMissionStats = async () =>
  MissionStats.findOneAndUpdate(
    { singletonKey: MISSION_STATS_SINGLETON_KEY },
    {
      $setOnInsert: {
        singletonKey: MISSION_STATS_SINGLETON_KEY,
        goal: DEFAULT_MISSION_GOAL,
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  );

const incrementMissionStats = async ({
  tablesCreatedDelta = 0,
  strangersConnectedDelta = 0,
}) => {
  const hasIncrement =
    tablesCreatedDelta !== 0 || strangersConnectedDelta !== 0;
  if (!hasIncrement) return ensureMissionStats();

  return MissionStats.findOneAndUpdate(
    { singletonKey: MISSION_STATS_SINGLETON_KEY },
    {
      $setOnInsert: {
        singletonKey: MISSION_STATS_SINGLETON_KEY,
        goal: DEFAULT_MISSION_GOAL,
      },
      $inc: {
        tablesCreatedTotal: tablesCreatedDelta,
        strangersConnectedTotal: strangersConnectedDelta,
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  );
};

// Helper function to calculate distance between two coordinates
function calculateDistance(lat1, lon1, lat2, lon2) {
  if (!lat1 || !lon1 || !lat2 || !lon2) return null;

  const R = 6371; // Earth's radius in kilometers
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distance in kilometers
}

// Check if a string looks like a valid Expo push token (API-only; app may not send token)
const isValidExpoPushToken = (token) => {
  if (!token || typeof token !== "string") return false;
  const t = token.trim();
  return (
    t.length > 0 &&
    (t.startsWith("ExponentPushToken[") || t.startsWith("ExpoPushToken["))
  );
};

// Helper function to create and send notifications
// In-app notification is always saved; push is best-effort only (no token or invalid token = no push, no failure)
// category is optional; when set, used for cap tracking (see createNotificationWithCaps).
// Event notifications are triggered from here (crons, POST /events, joins, etc.); caps and copy live in api/notifications/.
const createNotification = async ({
  userId,
  type,
  title,
  message,
  eventId,
  eventName,
  actorId,
  actorName,
  actorImage,
  category,
  skipPush,
}) => {
  try {
    // 1. Save to database (in-app notification) – always attempt
    const notification = new Notification({
      userId,
      type,
      title,
      message,
      eventId,
      eventName,
      actorId,
      actorName,
      actorImage,
      ...(category != null && { category }),
    });
    await notification.save();

    console.log(
      `[Notification] Saved ${type} notification (id=${notification._id}) for user ${userId} (eventId=${eventId || "none"})`,
    );

    // 2. Send push unless skipPush (e.g. worker will batch-send later)
    if (!skipPush) {
      const user = await User.findById(userId).select("pushToken").lean();
      const token = user?.pushToken;
      console.log(
        `[Notification] Push check for user=${userId}, type=${type}, token=${
          token ? `${String(token).slice(0, 20)}...` : "NONE"
        }`,
      );
      if (isValidExpoPushToken(token)) {
        console.log(
          `[Notification] Sending push for type=${type} to user=${userId}`,
        );
        try {
          await sendNotification(token, title, message, {
            type,
            eventId: eventId?.toString(),
            actorId: actorId?.toString(),
          });
        } catch (pushError) {
          console.error(
            `[Notification] Failed to send push to user ${userId}:`,
            pushError?.message || pushError,
          );
        }
      } else if (token) {
        console.log(
          `[Notification] User ${userId} has no valid Expo push token, skipping push`,
        );
      } else {
        console.log(
          `[Notification] User ${userId} has no pushToken stored, skipping push`,
        );
      }
    }

    console.log(
      `[Notification] Created ${type} notification for user ${userId}`,
    );
    return notification;
  } catch (error) {
    console.error("[Notification] Error creating notification:", error);
    throw error;
  }
};

// Cap-aware wrapper: checks FOMO/re_engagement limits before creating + sending. Use at API/cron boundaries.
// skipPush: when true, only save in-app notification (worker batches push later).
const createNotificationWithCaps = async (payload) => {
  const { userId, type } = payload;
  const category = getCategoryForType(type);
  if (
    category === "transactional" ||
    category === "discovery" ||
    category === "post_experience"
  ) {
    return createNotification({ ...payload, category });
  }
  const { allowed, reason } = await shouldSendNotification(userId, category);
  if (!allowed) {
    console.log(
      `[Notification] Skipping ${type} for user ${userId}: ${reason || "cap"}`,
    );
    return null;
  }
  return createNotification({ ...payload, category });
};

const NEARBY_NOTIFY_LIMIT = 200;
const MIN_FRESH_RECIPIENTS = 30;

// Exclude Cuddles users from event/activity notification batches (they use a different Expo project).
// Only ios-events populates event flows; ios-cuddles populates lookingFor and availability.
const EVENTS_ONLY_QUERY = {
  $and: [
    { $or: [{ lookingFor: { $exists: false } }, { lookingFor: { $size: 0 } }] },
    {
      $or: [
        { availability: { $exists: false } },
        { availability: { $size: 0 } },
      ],
    },
  ],
};

// Register nearby-notifications queue worker when Redis is available
const nearbyQueue = getQueue();
if (nearbyQueue) {
  nearbyQueue.process(1, async (job) => {
    const { type, eventId } = job.data || {};
    if (type === "event_nearby") {
      const event = await Event.findById(eventId)
        .populate("hostId", "name")
        .lean();
      if (!event) {
        console.warn("[Nearby Queue] event_nearby: event not found", eventId);
        return;
      }
      const hostId = event.hostId?._id || event.hostId;
      const hostName = (event.hostId && event.hostId.name) || "Someone";
      const [lng, lat] = event.location?.coordinates || [];
      if (lng == null || lat == null) return;
      const audienceQuery = {};
      if (event.audience === "women_only") audienceQuery.gender = "female";
      else if (event.audience === "men_only") audienceQuery.gender = "male";
      const recentlyNotifiedIds = (
        await getRecentlyNotifiedUserIds("event_nearby", DISCOVERY_COOLDOWN_MS)
      ).map((id) => new mongoose.Types.ObjectId(id));
      // Tier A: prefer users who haven't received event_nearby in the cooldown window.
      const tierAUsers = await User.aggregate([
        {
          $geoNear: {
            near: { type: "Point", coordinates: [lng, lat] },
            distanceField: "distance",
            maxDistance: 50000,
            spherical: true,
            query: {
              $and: [
                { _id: { $ne: new mongoose.Types.ObjectId(hostId) } },
                ...(recentlyNotifiedIds.length
                  ? [{ _id: { $nin: recentlyNotifiedIds } }]
                  : []),
                { pushToken: { $exists: true, $ne: null } },
                ...(audienceQuery.gender
                  ? [{ gender: audienceQuery.gender }]
                  : []),
                ...EVENTS_ONLY_QUERY.$and,
              ],
            },
          },
        },
        { $sample: { size: NEARBY_NOTIFY_LIMIT } },
        { $project: { _id: 1, pushToken: 1 } },
      ]);

      let nearbyUsers = tierAUsers;

      // Tier B fallback: if the fresh pool is too small, fill from recently-notified users so we never hit 0 recipients.
      if (
        nearbyUsers.length < MIN_FRESH_RECIPIENTS &&
        recentlyNotifiedIds.length > 0
      ) {
        const remaining = Math.max(0, NEARBY_NOTIFY_LIMIT - nearbyUsers.length);
        if (remaining > 0) {
          const tierBUsers = await User.aggregate([
            {
              $geoNear: {
                near: { type: "Point", coordinates: [lng, lat] },
                distanceField: "distance",
                maxDistance: 50000,
                spherical: true,
                query: {
                  $and: [
                    { _id: { $ne: new mongoose.Types.ObjectId(hostId) } },
                    { _id: { $in: recentlyNotifiedIds } },
                    { pushToken: { $exists: true, $ne: null } },
                    ...(audienceQuery.gender
                      ? [{ gender: audienceQuery.gender }]
                      : []),
                    ...EVENTS_ONLY_QUERY.$and,
                  ],
                },
              },
            },
            { $sample: { size: remaining } },
            { $project: { _id: 1, pushToken: 1 } },
          ]);
          nearbyUsers = [...nearbyUsers, ...tierBUsers];
        }
      }
      const eventNearbyStr = getStrings("en").eventNearby;
      const spotsOpen = Math.max(0, (event.capacity || 6) - 1);
      const title = interpolate(eventNearbyStr.title, {});
      const body = interpolate(eventNearbyStr.body, {
        name: hostName,
        activity: event.title || "",
        spotsOpen: String(spotsOpen),
      });
      const messages = [];
      for (const u of nearbyUsers) {
        const { allowed } = await shouldSendNotification(u._id, "discovery");
        if (!allowed) continue;
        await createNotificationWithCaps({
          userId: u._id,
          type: "event_nearby",
          title,
          message: body,
          eventId: event._id,
          eventName: event.title,
          actorId: hostId,
          actorName: hostName,
          skipPush: true,
        });
        if (u.pushToken)
          messages.push({
            to: u.pushToken,
            title,
            body,
            data: { type: "event_nearby", eventId: event._id.toString() },
          });
      }
      await sendNotificationBatch(messages);
      console.log(
        `[Nearby Queue] event_nearby: sent ${messages.length} notifications for event ${eventId}`,
      );
    } else if (type === "event_nearby_60") {
      const event = await Event.findById(eventId).lean();
      if (!event) {
        console.warn(
          "[Nearby Queue] event_nearby_60: event not found",
          eventId,
        );
        return;
      }
      const host = await User.findById(event.hostId).select("name").lean();
      const hostName = host?.name || "Someone";
      const participantIds = (event.participants || []).map((p) =>
        p.userId && p.userId._id ? p.userId._id : p.userId,
      );
      const excludeIds = [event.hostId, ...participantIds]
        .filter(Boolean)
        .map((id) => (id && id._id ? id._id : id));
      const [lng, lat] = event.location?.coordinates || [];
      if (lng == null || lat == null || excludeIds.length === 0) {
        await Event.updateOne(
          { _id: eventId },
          { sixtyPercentNotifSent: true },
        );
        return;
      }
      const audienceQuery = {};
      if (event.audience === "women_only") audienceQuery.gender = "female";
      else if (event.audience === "men_only") audienceQuery.gender = "male";
      const recentlyNotifiedIds60 = (
        await getRecentlyNotifiedUserIds(
          "table_filling_fast",
          DISCOVERY_COOLDOWN_MS,
        )
      ).map((id) => new mongoose.Types.ObjectId(id));
      const allExcludeIds = [
        ...excludeIds.map((id) => new mongoose.Types.ObjectId(id)),
        ...recentlyNotifiedIds60,
      ];
      const nearbyNotJoined = await User.aggregate([
        {
          $geoNear: {
            near: { type: "Point", coordinates: [lng, lat] },
            distanceField: "distance",
            maxDistance: 50000,
            spherical: true,
            query: {
              $and: [
                { _id: { $nin: allExcludeIds } },
                { pushToken: { $exists: true, $ne: null } },
                ...(audienceQuery.gender
                  ? [{ gender: audienceQuery.gender }]
                  : []),
                ...EVENTS_ONLY_QUERY.$and,
              ],
            },
          },
        },
        { $sample: { size: NEARBY_NOTIFY_LIMIT } },
        { $project: { _id: 1, pushToken: 1, preferredLanguage: 1 } },
      ]);
      const fillStrEn = getStrings("en").tableFillingFast;
      const messages = [];
      for (const u of nearbyNotJoined) {
        const { allowed } = await shouldSendNotification(u._id, "fomo");
        if (!allowed) continue;
        const str =
          u.preferredLanguage &&
          getStrings(u.preferredLanguage).tableFillingFast
            ? getStrings(u.preferredLanguage).tableFillingFast
            : fillStrEn;
        const notifTitle = interpolate(str.title, {
          name: hostName,
          activity: event.title || "",
        });
        const notifBody = str.body || "";
        await createNotificationWithCaps({
          userId: u._id,
          type: "table_filling_fast",
          title: notifTitle,
          message: notifBody,
          eventId: event._id,
          eventName: event.title,
          actorId: event.hostId,
          actorName: hostName,
          skipPush: true,
        });
        if (u.pushToken)
          messages.push({
            to: u.pushToken,
            title: notifTitle,
            body: notifBody,
            data: { type: "table_filling_fast", eventId: event._id.toString() },
          });
      }
      await sendNotificationBatch(messages);
      await Event.updateOne({ _id: eventId }, { sixtyPercentNotifSent: true });
      console.log(
        `[Nearby Queue] event_nearby_60: sent ${messages.length} notifications for event ${eventId}`,
      );
    } else if (type === "capetown_weekend") {
      const capetownStr = getStrings("en").capetownWeekend;
      if (!capetownStr) return;
      const title = capetownStr.title;
      const body = capetownStr.body;
      const users = await User.aggregate([
        {
          $geoNear: {
            near: { type: "Point", coordinates: [CAPETOWN_LNG, CAPETOWN_LAT] },
            distanceField: "distance",
            maxDistance: CAPETOWN_RADIUS_M,
            spherical: true,
            query: {
              $and: [
                { pushToken: { $exists: true, $ne: null } },
                ...EVENTS_ONLY_QUERY.$and,
              ],
            },
          },
        },
        { $limit: 500 },
        { $project: { _id: 1, pushToken: 1 } },
      ]);
      const messages = [];
      for (const u of users) {
        const { allowed } = await shouldSendNotification(
          u._id,
          "re_engagement",
        );
        if (!allowed) continue;
        await createNotificationWithCaps({
          userId: u._id,
          type: "capetown_weekend",
          title,
          message: body,
          skipPush: true,
        });
        if (u.pushToken)
          messages.push({
            to: u.pushToken,
            title,
            body,
            data: { type: "capetown_weekend" },
          });
      }
      if (messages.length > 0) {
        await sendNotificationBatch(messages);
        console.log(
          `[Nearby Queue] capetown_weekend: sent ${messages.length} notifications`,
        );
      }
    } else if (type === "regional_campaign") {
      const { campaignId } = job.data;
      console.log(
        `[Nearby Queue] regional_campaign: executing campaign ${campaignId}`,
      );
      await executeCampaign(campaignId, {
        shouldSendNotification,
        createNotificationWithCaps,
      });
      console.log(
        `[Nearby Queue] regional_campaign: finished campaign ${campaignId}`,
      );
    } else {
      console.warn("[Nearby Queue] Unknown job type:", type);
    }
  });
  console.log("[Nearby Queue] Worker registered for nearby-notifications");
}

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  bodyParser.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  }),
);
// Routes
app.use("/api/users", userRoutes);

app.get("/public/mission-stats", async (req, res) => {
  try {
    const stats = await ensureMissionStats();
    const goal =
      Number(stats.goal) > 0 ? Number(stats.goal) : DEFAULT_MISSION_GOAL;
    const strangersConnected = Math.max(
      0,
      Number(stats.strangersConnectedTotal) || 0,
    );
    const tablesCreated = Math.max(0, Number(stats.tablesCreatedTotal) || 0);
    const progressPercent =
      goal > 0 ? Math.min((strangersConnected / goal) * 100, 100) : 0;

    return res.status(200).json({
      strangersConnected,
      tablesCreated,
      goal,
      progressPercent,
      updatedAt: stats.updatedAt,
    });
  } catch (error) {
    console.error("Error fetching mission stats:", error);
    return res.status(500).json({
      message: "Error fetching mission stats",
      error: error.message,
    });
  }
});

app.get("/public/events/invitable-upcoming", async (req, res) => {
  try {
    const parsedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isFinite(parsedLimit)
      ? Math.min(Math.max(parsedLimit, 1), 50)
      : 12;
    const now = new Date();

    const events = await Event.find({
      websiteVisible: true,
      status: { $in: ["upcoming", "live", "full"] },
      startTime: { $gte: now },
    })
      .sort({ startTime: 1 })
      .limit(limit)
      .select(
        "_id title description startTime endTime status location coverImage isPaid priceAmount currency link organizerType websiteVisible",
      )
      .lean();

    const upcomingEvents = events
      .map((event) => ({
        ...event,
        status: computeNextEventStatus(event),
      }))
      .filter((event) => event.status !== "ended" && event.status !== "cancelled");

    const paidEvents = upcomingEvents.filter(
      (event) => event.organizerType === "invitable" && event.isPaid === true,
    );
    const freeCommunityEvents = upcomingEvents.filter(
      (event) => event.isPaid === false,
    );

    return res.status(200).json({
      events: paidEvents,
      paidEvents,
      freeCommunityEvents,
      count: paidEvents.length,
      totalCount: upcomingEvents.length,
    });
  } catch (error) {
    console.error("Error fetching Invitable upcoming events:", error);
    return res.status(500).json({
      message: "Error fetching Invitable upcoming events",
      error: error.message,
    });
  }
});

// controllers
const { getUnreadCounts } = require("./Controllers/conversationController");
const { profile } = require("console");

// Configure multer for file handling
const storage = multer.memoryStorage(); // Store files in memory
const upload = multer({ storage });
const imageUpload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const ok = ALLOWED_INPUT_MIME_TYPES.has(
      String(file?.mimetype || "").toLowerCase(),
    );
    if (!ok) return cb(new Error("Only jpeg/png/webp images are allowed"));
    cb(null, true);
  },
});

const imageUploadSingle = (req, res, next) => {
  imageUpload.single("file")(req, res, (err) => {
    if (!err) return next();
    const message = err.message || "Invalid upload";
    return res.status(400).json({ error: message });
  });
};

// Cloudinary configuration
cloudinary.config({
  cloud_name: "dmqt8wnrd",
  api_key: "362393959313675",
  api_secret: "sL1aM1tebd3pkvXD51c37_0EERg",
});

// MongoDB connection
mongoose
  .connect(
    "mongodb://cuddles:LNum9ZwrrcNDyl5c@ac-r0ymzab-shard-00-00.bdtblda.mongodb.net:27017,ac-r0ymzab-shard-00-01.bdtblda.mongodb.net:27017,ac-r0ymzab-shard-00-02.bdtblda.mongodb.net:27017/?ssl=true&replicaSet=atlas-ll9zih-shard-0&authSource=admin&retryWrites=true&w=majority",
  )
  .then(async () => {
    console.log("Connected to the Database");
  })
  .catch((error) => {
    console.log("Error connecting to the Database", error);
  });

http.listen(port, "0.0.0.0", () => {
  console.log(`Server is running on port ${port} and accessible from network`);
});

module.exports = mongoose;

// Socket.io connection
io.on("connection", (socket) => {
  // Listen for the join event and make the user join a specific room
  socket.on("join", ({ userId }) => {
    // Store the socket connection for this user
    userSockets.set(userId, socket.id);
    socket.join(userId); // User joins a room with their own userId
    // Emit a success message back to the client
    socket.emit("joinSuccess", {
      status: 200,
      message: "Joined room successfully",
    });
  });

  // Join a user to a specific group chat room
  socket.on("joinGroup", ({ userId, groupId }) => {
    socket.join(groupId);
    socket.emit("joinGroupSuccess", {
      status: 200,
      message: `Joined group ${groupId} successfully`,
    });
  });

  /// send group message
  socket.on("sendGroupMessage", async ({ senderId, groupId, message }) => {
    try {
      const newGroupMessage = new GroupMessage({
        groupId,
        senderId,
        message,
        timestamp: new Date(),
      });

      await newGroupMessage.save();
      io.to(groupId).emit("receiveGroupMessage", newGroupMessage);
      console.log(`Message sent to group ${groupId}:`, message);
    } catch (error) {
      console.error("Error sending group message:", error);
    }
  });

  // ============================================================
  // EVENT CHAT SOCKET EVENTS (Open Tables)
  // ============================================================

  // Join event chat room
  socket.on("joinEventChat", async ({ userId, eventId }) => {
    try {
      // Verify user is a participant of the event
      const event = await Event.findById(eventId);
      if (!event) {
        socket.emit("joinEventChatError", {
          status: 404,
          message: "Event not found",
        });
        return;
      }

      const isParticipant = event.participants.some(
        (p) => p.userId.toString() === userId,
      );
      if (!isParticipant) {
        socket.emit("joinEventChatError", {
          status: 403,
          message: "Only participants can join event chat",
        });
        return;
      }

      // Join the event chat room
      const roomName = `event_${eventId}`;
      socket.join(roomName);

      // Store the event room mapping for this socket
      if (!socket.eventRooms) {
        socket.eventRooms = new Set();
      }
      socket.eventRooms.add(roomName);

      socket.emit("joinEventChatSuccess", {
        status: 200,
        eventId,
        message: `Joined event chat successfully`,
      });

      console.log(`User ${userId} joined event chat: ${eventId}`);
    } catch (error) {
      console.error("Error joining event chat:", error);
      socket.emit("joinEventChatError", {
        status: 500,
        message: "Error joining event chat",
      });
    }
  });

  // Leave event chat room
  socket.on("leaveEventChat", ({ eventId }) => {
    const roomName = `event_${eventId}`;
    socket.leave(roomName);

    if (socket.eventRooms) {
      socket.eventRooms.delete(roomName);
    }

    socket.emit("leaveEventChatSuccess", {
      status: 200,
      eventId,
      message: "Left event chat successfully",
    });
  });

  // Send message to event chat
  socket.on(
    "sendEventMessage",
    async ({ senderId, eventId, message, type = "text", image }) => {
      try {
        // Verify user is a participant
        const event = await Event.findById(eventId);
        if (!event) {
          socket.emit("sendEventMessageError", {
            status: 404,
            message: "Event not found",
          });
          return;
        }

        const isParticipant = event.participants.some(
          (p) => p.userId.toString() === senderId,
        );
        if (!isParticipant) {
          socket.emit("sendEventMessageError", {
            status: 403,
            message: "Only participants can send messages",
          });
          return;
        }

        // Create and save the message
        const newEventMessage = new EventMessage({
          eventId,
          senderId,
          message: type === "text" ? message : undefined,
          type,
          image: type === "image" ? image : undefined,
          createdAt: new Date(),
        });

        await newEventMessage.save();

        // Populate sender info
        const populatedMessage = await EventMessage.findById(
          newEventMessage._id,
        ).populate("senderId", "name profileImages");

        // Emit to all users in the event room
        const roomName = `event_${eventId}`;
        io.to(roomName).emit("receiveEventMessage", {
          ...populatedMessage.toObject(),
          eventId,
        });

        console.log(`Event message sent to ${roomName}:`, message || "[image]");

        // Send push notifications to participants not in the room
        const sender = await User.findById(senderId).select("name");
        const participantsToNotify = await User.find({
          _id: {
            $in: event.participants
              .filter((p) => p.userId.toString() !== senderId)
              .map((p) => p.userId),
          },
          pushToken: { $exists: true, $ne: null },
        }).select("pushToken");

        const notificationMessage =
          type === "image"
            ? `${sender.name} sent an image`
            : message.length > 50
              ? `${message.substring(0, 50)}...`
              : message;

        for (const participant of participantsToNotify) {
          try {
            await sendNotification(
              participant.pushToken,
              `${event.title}`,
              `${sender.name}: ${notificationMessage}`,
              { type: "event_chat", eventId: eventId.toString() },
            );
          } catch (notifError) {
            console.error(
              "Error sending event message notification:",
              notifError,
            );
          }
        }
      } catch (error) {
        console.error("Error sending event message:", error);
        socket.emit("sendEventMessageError", {
          status: 500,
          message: "Error sending message",
        });
      }
    },
  );

  // Send system message to event chat (e.g., "John joined the table")
  socket.on("sendEventSystemMessage", async ({ eventId, message }) => {
    try {
      const event = await Event.findById(eventId);
      if (!event) return;

      // Create system message
      const systemMessage = new EventMessage({
        eventId,
        senderId: event.hostId, // Use host as sender for system messages
        message,
        type: "system",
        createdAt: new Date(),
      });

      await systemMessage.save();

      // Emit to event room
      const roomName = `event_${eventId}`;
      io.to(roomName).emit("receiveEventMessage", {
        ...systemMessage.toObject(),
        eventId,
        isSystem: true,
      });
    } catch (error) {
      console.error("Error sending system message:", error);
    }
  });

  // Listen for incoming messages
  socket.on("sendMessage", async (data) => {
    const { senderId, receiverId, message, image, type } = data;
    console.log("Received message:", {
      senderId,
      receiverId,
      message,
      type,
      hasImage: !!image,
    });

    try {
      // Create a new message object
      const newMessage = {
        senderId,
        receiverId,
        message,
        type,
        image: type === "image" ? image : undefined,
        timestamp: new Date(),
        read: false,
      };

      // Save the message to the database
      const savedMessage = await Chat.create(newMessage);
      console.log("Message saved to database:", savedMessage);

      // Emit the message to the receiver if they are online
      const receiverSocketId = userSockets.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit("receiveMessage", savedMessage);
      }

      // Send push notification if receiver has a push token
      const receiver = await User.findById(receiverId);
      if (receiver?.pushToken) {
        const sender = await User.findById(senderId);
        const notificationMessage =
          type === "image" ? `${sender.name} sent you an image` : message;

        await sendPushNotification(
          receiver.pushToken,
          sender.name,
          notificationMessage,
          { type: "dm", senderId: senderId.toString() },
        );
      }

      // Update or create conversation for the sender
      await User.findByIdAndUpdate(
        senderId,
        {
          $push: {
            conversations: {
              receiverId,
              unreadMessagesCount: 0,
            },
          },
        },
        { upsert: true },
      );

      // Update or create conversation for the receiver
      await User.findByIdAndUpdate(
        receiverId,
        {
          $push: {
            conversations: {
              receiverId: senderId,
              unreadMessagesCount: 1,
            },
          },
        },
        { upsert: true },
      );
    } catch (error) {
      console.error("Error handling message:", error);
    }
  });

  // Listen for marking messages as read
  socket.on("markAsRead", async ({ userId, senderId }) => {
    try {
      // Reset the unread messages count to zero
      const updatedUser = await User.findOneAndUpdate(
        { _id: senderId, "conversations.receiverId": userId },
        { $set: { "conversations.$.unreadMessagesCount": 0 } },
        { new: true },
      );

      // Optionally, you can emit an update event to the sender or other relevant clients
      if (updatedUser) {
        // Emit an event to notify about the updated unread count
        io.to(senderId).emit("updateUnreadCount", { senderId, unreadCount: 0 });
      }
    } catch (error) {
      console.error("Error marking messages as read:", error);
    }
  });

  app.get("/group/messages/:groupName", async (req, res) => {
    const { groupName } = req.params;

    try {
      // Validate the groupName
      if (!["Good Times", "Vibes", "Friendships"].includes(groupName)) {
        return res.status(400).json({ message: "Invalid group name" });
      }

      const messages = await GroupMessage.find({ groupName })
        .sort({ createdAt: 1 }) // Sort by createdAt in ascending order
        .select("senderId message createdAt"); // Select only necessary fields

      res.status(200).json(messages);
    } catch (error) {
      console.error("Error fetching group messages:", error);
      res.status(500).json({ message: "Server error" });
    }
  });

  // set read messages to true
  app.post("/messages/read", async (req, res) => {
    const { userId, senderId } = req.body;

    try {
      // Find and update the unread messages for the specified conversation
      const updatedMessages = await Chat.updateMany(
        {
          $or: [
            { senderId: senderId, receiverId: userId, read: false }, // Messages sent by the sender
            { senderId: userId, receiverId: senderId, read: false }, // Messages sent by the receiver
          ],
        },
        { $set: { read: true } },
        { multi: true }, // Update multiple documents
      );

      if (updatedMessages.nModified === 0) {
        return res.status(404).json({ message: "No unread messages found" });
      }

      // Update the user's conversation to reset unread count
      const user = await User.findOneAndUpdate(
        { _id: userId, "conversations.receiverId": senderId },
        { $set: { "conversations.$.unreadMessagesCount": 0 } },
        { new: true },
      );

      if (!user) {
        return res.status(404).json({ message: "Conversation not found" });
      }

      return res.status(200).json({ message: "Messages marked as read", user });
    } catch (error) {
      console.error("Error marking messages as read:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  });

  // Handle user disconnect
  socket.on("disconnect", () => {
    // Remove the user's socket connection when they disconnect
    for (const [userId, socketId] of userSockets.entries()) {
      if (socketId === socket.id) {
        userSockets.delete(userId);
        break;
      }
    }
  });
});

// Register endpoint
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, age, platform } = req.body;

    console.log(name, email, age);

    // Validate and normalize platform
    const validPlatforms = ["ios", "android", "unknown"];
    const normalizedPlatform =
      platform && validPlatforms.includes(platform.toLowerCase())
        ? platform.toLowerCase()
        : "unknown";

    // Validate required fields for all users
    if (!name || !email || !age) {
      return res
        .status(400)
        .json({ message: "Name, email, and age are required" });
    }

    // Ensure email is in a valid format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    // Convert email to lowercase for consistency
    const normalizedEmail = email.toLowerCase();

    // Check if the user already exists
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      // Generate a JWT token for the existing user
      const token = jwt.sign({ userId: existingUser._id }, secretKey);

      // Respond with the token and a message indicating the user already exists
      return res.status(200).json({
        message: "User already exists. Here's your token.",
        token,
        userId: existingUser._id,
      });
    }

    let hashedPassword = null;

    // If a password is provided, validate and hash it
    if (password) {
      if (password.length < 8) {
        return res.status(400).json({
          message: "Password must be at least 8 characters long",
        });
      }
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    // Create a new user
    const newUser = new User({
      name,
      email: normalizedEmail,
      password: hashedPassword, // Will be null if no password is provided
      age,
      platform: normalizedPlatform,
    });

    // Generate a verification token
    newUser.VerificationToken = crypto.randomBytes(20).toString("hex");

    // Save the new user to the database
    await newUser.save();

    // Generate a JWT token
    const token = jwt.sign({ userId: newUser._id }, secretKey);

    // Respond with success
    res.status(201).json({ token, userId: newUser._id });
  } catch (error) {
    console.error("Error during registration:", error);

    // MongoDB validation errors
    if (error.name === "ValidationError") {
      return res.status(400).json({
        message: "Validation error",
        details: error.errors,
      });
    }

    // Handle duplicate key errors (e.g., email already exists)
    if (error.code === 11000) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Generic error handling
    res.status(500).json({
      message: "An unexpected error occurred during registration",
      error: error.message,
    });
  }
});

// Change Password API
app.post("/change-password/:userId", async (req, res) => {
  "";
  try {
    const { userId } = req.params;
    const { currentPassword, newPassword } = req.body;

    // Check if both current and new password are provided
    if (!currentPassword || !newPassword) {
      return res
        .status(400)
        .json({ message: "Please provide both current and new password." });
    }

    // Find the user by their ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Compare the current password with the user's hashed password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect current password." });
    }

    // Hash the new password
    const saltRounds = 10;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password in the database
    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "cuddlesquery@gmail.com",
    pass: "nlvj jxji vkni ftxv",
  },
  pool: true, // Use pooled connections
  maxConnections: 5, // Limit concurrent connections
  maxMessages: 100, // Limit messages per connection
  rateDelta: 1000, // How many messages to send per second
  rateLimit: 5, // Max number of messages per rateDelta
});

// Verify transporter configuration
transporter.verify(function (error, success) {
  if (error) {
    console.error("Transporter verification failed:", error);
  } else {
    console.log("Transporter is ready to send emails");
  }
});

// Helper function to send email with retry logic
const sendEmailWithRetry = async (mailOptions, maxRetries = 3) => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await transporter.sendMail(mailOptions);
      console.log(
        `Email sent successfully on attempt ${attempt}:`,
        result.messageId,
      );
      return { success: true, messageId: result.messageId };
    } catch (error) {
      console.error(`Email send attempt ${attempt} failed:`, error);
      if (attempt === maxRetries) {
        return { success: false, error: error.message };
      }
      // Wait before retrying (exponential backoff)
      await new Promise((resolve) =>
        setTimeout(resolve, Math.pow(2, attempt) * 1000),
      );
    }
  }
  return { success: false, error: "Max retries exceeded" };
};

// Send verification email
const sendVerificationEmail = async (email, VerificationToken) => {
  const mailOptions = {
    from: "cuddles.com",
    to: email,
    subject: "Email verification",
    text: `Click on this link to verify your email: https://cuddles-batcat.onrender.com/verify/${VerificationToken}`,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.log("Error sending the verification email", error);
  }
};

// Verify user
app.get("/verify/:token", async (req, res) => {
  try {
    const token = req.params.token;
    const user = await User.findOne({ VerificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid verification code" });
    }

    // Mark the user as verified
    user.verified = true;
    user.VerificationToken = undefined;

    await user.save();

    res.status(200).json({ message: "Email verified" });
  } catch (error) {
    console.log("Email verification failed", error);
    res.status(500).json({ message: "Email verification failed" });
  }
});

const secretKey = process.env.JWT_SECRET || "dev-local-jwt-secret-change-me";
if (!process.env.JWT_SECRET) {
  console.warn(
    "[Auth] JWT_SECRET is not set; using development fallback secret.",
  );
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match)
    return res
      .status(401)
      .json({ message: "Missing Authorization Bearer token" });

  try {
    const decoded = jwt.verify(match[1], secretKey);
    if (!decoded?.userId)
      return res.status(401).json({ message: "Invalid token payload" });
    req.authUserId = decoded.userId;
    return next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

app.use("/", createPaymentRoutes(requireAuth));

// HTTPS redirect bridge for payment providers that require http/https redirects.
// Usage example:
// https://your-api-domain/stitch/redirect?deep_link=cuddles-events://event/123
app.get("/stitch/redirect", (req, res) => {
  const deepLink = String(req.query.deep_link || "").trim();
  if (!deepLink) {
    return res
      .status(400)
      .send("Missing deep_link query parameter for app redirect.");
  }

  const escapedDeepLink = deepLink.replace(/'/g, "\\'");
  return res.status(200).set("Content-Type", "text/html; charset=utf-8")
    .send(`<!doctype html>
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Returning to Cuddles</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 24px; color: #111; }
      button { border: 0; border-radius: 10px; padding: 12px 16px; background: #111827; color: #fff; font-weight: 600; }
    </style>
  </head>
  <body>
    <p>Returning you to the app...</p>
    <button onclick="window.location.href='${escapedDeepLink}'">Open Cuddles</button>
    <script>
      window.location.href = '${escapedDeepLink}';
      setTimeout(function () {
        var btn = document.querySelector('button');
        if (btn) btn.style.display = 'inline-block';
      }, 1200);
    </script>
  </body>
</html>`);
});

//login user

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Login attempt for email:", email);

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      console.log("no user ");
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Check if password is null
    if (!user.password) {
      console.log("User has no password set");
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, secretKey);

    // Send back both the token and user ID
    res.status(200).json({ token, userId: user._id });
  } catch (error) {
    console.log("Error logging in the user", error);
    res.status(500).json({ message: "Login failed" });
  }
});
//gender change endpoint

app.put("/users/:userId/gender", async (req, res) => {
  try {
    const { userId } = req.params;
    const { gender } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { gender: gender },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res.status(200).json({ message: "user gender updated Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating user gender", error });
  }
});

// gender preferences

app.put("/users/:userId/preferences", async (req, res) => {
  try {
    const { userId } = req.params;
    const { preferences } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { preferences: preferences },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res.status(200).json({ message: "user gender updated Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating user gender", error });
  }
});
//description endpoint

app.put("/users/:userId/description", async (req, res) => {
  try {
    const { userId } = req.params;
    const { description } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { description: description },
      { new: true },
    );
    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res
      .status(200)
      .json({ message: "user description updated Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "error updating the users description" });
  }
});

// Update Instagram URL
app.put("/users/:userId/instagram", async (req, res) => {
  try {
    const { userId } = req.params;
    const { instagramUrl } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { instagramUrl: instagramUrl || "" },
      { new: true },
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({ message: "Instagram updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating Instagram" });
  }
});

// set interest endpoint

app.put("/users/:userId/interests/add", async (req, res) => {
  try {
    const { userId } = req.params;
    const { interests } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { interests: interests } },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }
    return res
      .status(200)
      .json({ message: "user interestts added Succesfully" });
  } catch (error) {
    res.status(500).json({ message: "error updating the users interests" });
  }
});

//remove interests

app.delete("/users/:userId/interests/remove", async (req, res) => {
  try {
    const { userId } = req.params;
    const { interest } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { interests: interest } }, // Remove a single interest
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res
      .status(200)
      .json({ message: "User interest removed successfully" });
  } catch (error) {
    res.status(500).json({
      message: "Error removing the user's interest",
      error: error.message,
    });
  }
});

//looking for endpoint

app.put("/users/:userId/lookingfor/add", async (req, res) => {
  try {
    const { userId } = req.params;
    const { lookingFor } = req.body;

    const validOptions = ["Friendship", "Goodtime", "Long term relationship"];

    if (
      !Array.isArray(lookingFor) ||
      lookingFor.some((item) => !validOptions.includes(item))
    ) {
      return res.status(400).json({
        message:
          "Invalid lookingFor data. Please choose from 'friendship', 'goodtime', or 'long term relationship'.",
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { lookingFor: { $each: lookingFor } } },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res
      .status(200)
      .json({ message: "User's 'looking for' updated successfully", user });
  } catch (error) {
    console.error("Error updating 'looking for':", error);
    return res
      .status(500)
      .json({ message: "Error updating the user's 'looking for'" });
  }
});

app.put("/users/:userId/availability/add", async (req, res) => {
  try {
    const { userId } = req.params;
    const { availability } = req.body;

    const validOptions = ["morning", "afternoon", "evening"];

    if (
      !Array.isArray(availability) ||
      availability.some((item) => !validOptions.includes(item))
    ) {
      return res.status(400).json({
        message:
          "Invalid availability data. Please choose from 'morning', 'afternoon', or 'evening'.",
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $addToSet: { availability: { $each: availability } } },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res
      .status(200)
      .json({ message: "User's 'looking for' updated successfully", user });
  } catch (error) {
    console.error("Error updating 'looking for':", error);
    return res
      .status(500)
      .json({ message: "Error updating the user's 'availability'" });
  }
});

app.put("/users/:userId/cuddle-preference", async (req, res) => {
  try {
    const { userId } = req.params;
    let { expectations } = req.body;

    if (!Array.isArray(expectations) || expectations.length === 0) {
      return res
        .status(400)
        .json({ message: "Preferences should be a non-empty array." });
    }

    // Sanitize input: Remove empty values & trim whitespace
    expectations = expectations
      .map((item) => (typeof item === "string" ? item.trim() : null))
      .filter((item) => item);

    if (expectations.length === 0) {
      return res
        .status(400)
        .json({ message: "Preferences cannot be empty after sanitization." });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { expectations },
      { new: true, runValidators: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "Cuddle preferences updated successfully",
      expectations: user.expectations, // Return updated preferences
    });
  } catch (error) {
    console.error("Error updating cuddle expectations:", error);
    return res.status(500).json({
      message: "Error updating the user's cuddle expectations",
      error: error.message,
    });
  }
});

// Konkatsu onboarding: marriage timeline
app.put("/users/:userId/marriage-timeline", async (req, res) => {
  try {
    const { userId } = req.params;
    const { marriageTimeline } = req.body;

    const valid = [
      "within_1_year",
      "1_to_2_years",
      "2_to_3_years",
      "3_plus_years",
      "when_right_person",
    ];

    if (!marriageTimeline || !valid.includes(marriageTimeline)) {
      return res.status(400).json({
        message: `Invalid marriageTimeline. Must be one of: ${valid.join(", ")}`,
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { marriageTimeline },
      { new: true, runValidators: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "Marriage timeline updated successfully",
      marriageTimeline: user.marriageTimeline,
    });
  } catch (error) {
    console.error("Error updating marriage timeline:", error);
    return res.status(500).json({
      message: "Error updating marriage timeline",
      error: error.message,
    });
  }
});

// Konkatsu onboarding: children preference
app.put("/users/:userId/children-preference", async (req, res) => {
  try {
    const { userId } = req.params;
    const { childrenPreference } = req.body;

    const valid = [
      "want_children",
      "dont_want_children",
      "open_to_discussion",
      "already_have_children",
    ];

    if (!childrenPreference || !valid.includes(childrenPreference)) {
      return res.status(400).json({
        message: `Invalid childrenPreference. Must be one of: ${valid.join(", ")}`,
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { childrenPreference },
      { new: true, runValidators: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "Children preference updated successfully",
      childrenPreference: user.childrenPreference,
    });
  } catch (error) {
    console.error("Error updating children preference:", error);
    return res.status(500).json({
      message: "Error updating children preference",
      error: error.message,
    });
  }
});

// Konkatsu onboarding: relocation openness
app.put("/users/:userId/relocation-openness", async (req, res) => {
  try {
    const { userId } = req.params;
    const { relocationOpenness } = req.body;

    const valid = ["willing_to_relocate", "prefer_local", "open_to_discussion"];

    if (!relocationOpenness || !valid.includes(relocationOpenness)) {
      return res.status(400).json({
        message: `Invalid relocationOpenness. Must be one of: ${valid.join(", ")}`,
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { relocationOpenness },
      { new: true, runValidators: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "Relocation openness updated successfully",
      relocationOpenness: user.relocationOpenness,
    });
  } catch (error) {
    console.error("Error updating relocation openness:", error);
    return res.status(500).json({
      message: "Error updating relocation openness",
      error: error.message,
    });
  }
});

// DELETE route to remove an item from the lookingFor array
app.delete("/users/:userId/lookingfor/remove", async (req, res) => {
  try {
    const { userId } = req.params;
    const { lookingForItem } = req.body;

    // Validate the lookingForItem is a string
    if (typeof lookingForItem !== "string") {
      return res
        .status(400)
        .json({ message: "Invalid 'lookingForItem'. Must be a string." });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $pull: { lookingFor: lookingForItem } },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "User 'looking for' item removed successfully",
      updatedLookingFor: user.lookingFor,
    });
  } catch (error) {
    console.error("Error removing 'looking for' item:", error);
    return res.status(500).json({
      message: "Error removing the user's 'looking for' item",
      error: error.message,
    });
  }
});

app.get("/users/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const userData = await User.findById(userId);

    if (!userData) {
      return res.status(404).json({ message: "user data not found" });
    }
    return res.status(200).json(userData);
  } catch (error) {
    res.status(500).json({ message: "error fetching the users data" });
  }
});

// Get relationship status between two users
app.get("/users/:userId/relationship/:otherUserId", async (req, res) => {
  try {
    const { userId, otherUserId } = req.params;

    if (
      !mongoose.Types.ObjectId.isValid(userId) ||
      !mongoose.Types.ObjectId.isValid(otherUserId)
    ) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const currentUser = await User.findById(userId).select(
      "Matches crushes recievedLikes",
    );
    const otherUser = await User.findById(otherUserId).select(
      "Matches crushes recievedLikes",
    );

    if (!currentUser || !otherUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if users are matched (mutual)
    const isMatched = currentUser.Matches.some(
      (id) => id.toString() === otherUserId,
    );

    // Check if current user is following (has liked) the other user
    const isFollowing = currentUser.crushes.some(
      (id) => id.toString() === otherUserId,
    );

    // Check if other user is following (has liked) the current user
    const isFollowedBy = otherUser.crushes.some(
      (id) => id.toString() === userId,
    );

    return res.status(200).json({
      isMatched,
      isFollowing,
      isFollowedBy,
    });
  } catch (error) {
    console.error("Error fetching relationship status:", error);
    res.status(500).json({
      message: "Error fetching relationship status",
      error: error.message,
    });
  }
});

// Check whether two users can connect (shared checked-in activity via coAttendees ledger)
app.get("/users/:userId/connect-eligibility/:otherUserId", async (req, res) => {
  try {
    const { userId, otherUserId } = req.params;

    if (
      !mongoose.Types.ObjectId.isValid(userId) ||
      !mongoose.Types.ObjectId.isValid(otherUserId)
    ) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const user = await User.findById(userId).select("coAttendees").lean();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const canConnect = (user.coAttendees || []).some(
      (id) => id.toString() === otherUserId,
    );

    return res.status(200).json({ canConnect });
  } catch (error) {
    console.error("Error checking connect eligibility:", error);
    res.status(500).json({
      message: "Error checking connect eligibility",
      error: error.message,
    });
  }
});

//image upload

app.post("/users/:userId/upload", imageUploadSingle, async (req, res) => {
  const userId = req.params.userId;

  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    let normalized;
    try {
      normalized = await normalizeProfileImageToJpeg(
        req.file.buffer,
        req.file.mimetype,
      );
    } catch (e) {
      return res.status(400).json({ error: e?.message || "Invalid image" });
    }

    const key = buildUserImageKey({
      userId,
      mimetype: normalized.contentType,
      originalname: req.file.originalname,
      extOverride: normalized.extension,
    });

    const { url: imageUrl } = await uploadImageBufferToR2({
      buffer: normalized.buffer,
      contentType: normalized.contentType,
      key,
    });

    // Step 3: Update the user's profile with the uploaded image URL
    if (imageUrl) {
      console.log(userId, imageUrl);
      const user = await User.findByIdAndUpdate(
        userId,
        { $addToSet: { profileImages: imageUrl } },
        { new: true },
      );

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
    }

    return res.status(200).json({ message: "Upload was a success", imageUrl });
  } catch (error) {
    console.error("File upload failed:", error);
    res.status(500).json({ error: "File upload failed" });
  }
});

/** Event cover image (R2) — upload before POST /events so create payload can include coverImage URL. */
app.post("/events/upload-image", imageUploadSingle, async (req, res) => {
  const userId = req.body?.userId;

  if (!userId) {
    return res.status(400).json({ error: "userId required" });
  }

  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    let normalized;
    try {
      normalized = await normalizeProfileImageToJpeg(
        req.file.buffer,
        req.file.mimetype,
      );
    } catch (e) {
      return res.status(400).json({ error: e?.message || "Invalid image" });
    }

    const key = buildEventImageKey({
      userId,
      mimetype: normalized.contentType,
      originalname: req.file.originalname,
      extOverride: normalized.extension,
    });

    const { url: imageUrl } = await uploadImageBufferToR2({
      buffer: normalized.buffer,
      contentType: normalized.contentType,
      key,
    });

    return res.status(200).json({ imageUrl });
  } catch (error) {
    console.error("[events/upload-image] failed:", error);
    res.status(500).json({ error: "Upload failed" });
  }
});

// endpoint to fetch users

app.get("/profiles", async (req, res) => {
  try {
    const {
      userId,
      gender,
      minAge = "21",
      maxAge = "100",
      longitude,
      latitude,
      maxDistance = "50",
    } = req.query;

    const parsedMaxDistanceKm =
      maxDistance && !isNaN(parseFloat(maxDistance))
        ? parseFloat(maxDistance)
        : 50;
    const maxDistanceMeters = parsedMaxDistanceKm * 1000;

    // Keep discovery focused on recently created accounts (last 60 days)
    const recentAccountThreshold = new Date();
    recentAccountThreshold.setDate(recentAccountThreshold.getDate() - 60);

    // Input validation
    if (!mongoose.Types.ObjectId.isValid(userId) || !gender) {
      return res
        .status(400)
        .json({ message: "Invalid userId or missing gender" });
    }

    // Fetch only needed fields from current user
    const currentUser = await User.findById(userId)
      .select("gender Matches crushes profileDislikes location")
      .lean();

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Get user's country from their location object
    const userCountry = currentUser.location?.country;

    // Convert all ObjectIds to strings for consistent handling
    const userIdStr = userId.toString();
    const matchIds = (currentUser.Matches || []).map((id) => id.toString());
    const crushIds = (currentUser.crushes || []).map((id) => id.toString());
    const dislikeIds = (currentUser.profileDislikes || []).map((id) =>
      id.toString(),
    );

    // All IDs to exclude
    const excludedIds = [userIdStr, ...matchIds, ...crushIds, ...dislikeIds];

    // Convert back to ObjectIds for MongoDB
    const excludedObjectIds = excludedIds.map((id) =>
      mongoose.Types.ObjectId.isValid(id)
        ? new mongoose.Types.ObjectId(id)
        : id,
    );

    // Determine gender filter
    const genderFilter =
      gender === "both"
        ? currentUser.gender === "male"
          ? "female"
          : "male"
        : gender;

    // Base query criteria - optimized filters for better performance
    const baseMatch = {
      _id: { $nin: excludedObjectIds },
      gender: genderFilter,
      age: {
        $gte: minAge.toString(),
        $lte: maxAge.toString(),
      },
      profileImages: { $exists: true, $ne: [] }, // Faster than $not: { $size: 0 }
      anonymous: { $ne: true }, // Simpler than $or with $exists
      flagged: { $ne: true }, // Simpler than $and/$or with $exists
      // Recency is based on account creation time
      createdAt: { $gte: recentAccountThreshold },
    };

    // Projection to limit returned fields for better performance
    const profileProjection = {
      _id: 1,
      name: 1,
      age: 1,
      gender: 1,
      profileImages: 1,
      description: 1,
      interests: 1,
      verified: 1,
      location: 1,
      occupation: 1,
      university: 1,
      preferences: 1,
      availability: 1,
      expectations: 1,
      lookingFor: 1,
      marriageTimeline: 1,
      childrenPreference: 1,
      relocationOpenness: 1,
      distance: 1,
      priority: 1,
      createdAt: 1,
    };

    let profiles = [];
    let hasLocation = false;

    // Function to get profiles with country filter - optimized with $facet
    const getProfilesWithCountry = async (countryFilter = true) => {
      const query = { ...baseMatch };
      if (countryFilter && userCountry) {
        // Only add country filter here when we want same country
        query["location.country"] = userCountry;
      } else {
        // When searching other countries, ensure we get profiles with a country set but not user's country
        query["location.country"] = { $exists: true, $ne: userCountry };
      }

      let countryProfiles = [];

      // Try to get nearby profiles first if location is provided
      if (longitude && latitude) {
        try {
          const nearbyProfiles = await User.aggregate([
            {
              $geoNear: {
                near: {
                  type: "Point",
                  coordinates: [parseFloat(longitude), parseFloat(latitude)],
                },
                distanceField: "distance",
                maxDistance: maxDistanceMeters,
                spherical: true,
                query: query,
                distanceMultiplier: 0.001,
                key: "location",
              },
            },
            { $sort: { priority: -1, createdAt: -1 } },
            { $project: profileProjection },
            { $limit: 20 },
          ]).option({ maxTimeMS: 5000 });

          countryProfiles = nearbyProfiles;
          hasLocation = true;
        } catch (error) {
          console.error("❌ Error in geospatial query:", error);
        }
      }

      // If we don't have enough profiles, use $facet to get both priority and newest in one query
      if (countryProfiles.length < 20) {
        const existingProfileIds = countryProfiles.map((p) =>
          mongoose.Types.ObjectId.isValid(p._id)
            ? new mongoose.Types.ObjectId(p._id)
            : p._id,
        );
        const neededProfiles = 20 - countryProfiles.length;

        // Combine priority and newest non-priority queries using $facet for single DB round-trip
        const facetResults = await User.aggregate([
          {
            $match: {
              _id: { $nin: [...excludedObjectIds, ...existingProfileIds] },
              ...query,
            },
          },
          {
            $facet: {
              priorityUsers: [
                { $match: { priority: 1 } },
                { $sort: { createdAt: -1 } },
                { $project: profileProjection },
                { $limit: neededProfiles },
              ],
              nonPriorityUsers: [
                { $match: { priority: { $ne: 1 } } },
                { $sort: { createdAt: -1 } },
                { $project: profileProjection },
                { $limit: neededProfiles },
              ],
            },
          },
        ]).option({ maxTimeMS: 5000 });

        if (facetResults.length > 0) {
          const { priorityUsers = [], nonPriorityUsers = [] } = facetResults[0];

          // Add priority users first
          priorityUsers.forEach((p) => {
            const idStr = p._id.toString();
            if (!existingProfileIds.some((id) => id.toString() === idStr)) {
              countryProfiles.push(p);
            }
          });
          console.log(`⭐ Found ${priorityUsers.length} priority profiles`);

          // Add newest non-priority users that aren't already included
          const stillNeeded = 20 - countryProfiles.length;
          if (stillNeeded > 0) {
            const existingIds = new Set(
              countryProfiles.map((p) => p._id.toString()),
            );
            const uniqueNonPriority = nonPriorityUsers.filter(
              (p) => !existingIds.has(p._id.toString()),
            );
            countryProfiles.push(...uniqueNonPriority.slice(0, stillNeeded));
          }
        }
      }

      return countryProfiles;
    };

    if (userCountry) {
      // Country is known — only show profiles from the same country, never backfill with other countries
      profiles = await getProfilesWithCountry(true);
    } else {
      // Country not yet resolved — use distance-based query with no country filter
      const query = { ...baseMatch };
      if (longitude && latitude) {
        try {
          profiles = await User.aggregate([
            {
              $geoNear: {
                near: {
                  type: "Point",
                  coordinates: [parseFloat(longitude), parseFloat(latitude)],
                },
                distanceField: "distance",
                maxDistance: maxDistanceMeters,
                spherical: true,
                query: query,
                distanceMultiplier: 0.001,
                key: "location",
              },
            },
            { $sort: { priority: -1, createdAt: -1 } },
            { $project: profileProjection },
            { $limit: 20 },
          ]).option({ maxTimeMS: 5000 });
          hasLocation = true;
        } catch (error) {
          console.error("Error in geo query for user without country:", error);
        }
      }

      // If geo returned nothing, do a basic query as last resort
      if (profiles.length === 0) {
        profiles = await User.find(query)
          .select(Object.keys(profileProjection).join(" "))
          .sort({ priority: -1, createdAt: -1 })
          .limit(20)
          .lean();
      }

      // Attempt to resolve and save the user's country for future requests.
      // IMPORTANT: await the async function so errors are caught here and do not
      // become unhandled promise rejections (which can crash the server).
      if (longitude && latitude) {
        try {
          await updateUserCountry(userId);
        } catch (countryErr) {
          console.error(
            "Failed to resolve user country in background:",
            countryErr?.message || countryErr,
          );
        }
      }
    }

    const rankedProfiles = profiles;

    // Calculate distances if location is provided
    if (hasLocation && rankedProfiles.length > 0) {
      const parsedLong = parseFloat(longitude);
      const parsedLat = parseFloat(latitude);

      rankedProfiles.forEach((profile) => {
        if (!profile.distance && profile.location?.coordinates) {
          profile.distance = calculateDistance(
            parsedLat,
            parsedLong,
            profile.location.coordinates[1],
            profile.location.coordinates[0],
          );
        }
      });
    }

    // Boost impression tracking: increment impressionCount for any active-boosted profiles shown
    if (rankedProfiles.length > 0) {
      try {
        const now = new Date();
        const boostedIds = rankedProfiles
          .map((p) => p._id?.toString())
          .filter(Boolean);
        await Boost.updateMany(
          {
            userId: { $in: boostedIds },
            status: "active",
            expiresAt: { $gt: now },
          },
          { $inc: { impressionCount: 1 } },
        );
      } catch (impressionErr) {
        console.error(
          "[Boost] Impression tracking error:",
          impressionErr?.message,
        );
      }
    }

    return res.status(200).json({
      profiles: rankedProfiles,
      totalCount: rankedProfiles.length,
      nearbyCount: rankedProfiles.filter((p) => p.distance != null).length,
      userCountry: userCountry || "Unknown",
      sameCountryCount: rankedProfiles.filter(
        (p) => p.location?.country === userCountry,
      ).length,
    });
  } catch (error) {
    console.error("Error fetching user profiles:", error);
    res.status(500).json({ message: "Error fetching user profiles" });
  }
});

app.post("/likeprofile", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId).select(
      "pushToken recievedLikes",
    );

    // Gate: must have attended at least one shared activity (coAttendees)
    if (
      currentUser &&
      !(currentUser.coAttendees || []).some(
        (id) => id.toString() === selectedUserId,
      )
    ) {
      return res.status(403).json({
        message:
          "You need to have attended at least 1 activity with this person before you can connect with them.",
      });
    }

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user has already liked the selected user
    const alreadyLiked = selectedUser.recievedLikes.includes(currentUserId);
    const alreadyCrush = currentUser.crushes.includes(selectedUserId);

    if (alreadyLiked || alreadyCrush) {
      console.log("You already liked this user.");
      return res
        .status(400)
        .json({ message: "You have already liked this user." });
    }

    // Update the recipient's likes if not already liked
    await User.findByIdAndUpdate(selectedUserId, {
      $push: { recievedLikes: currentUserId },
    });

    // Update the current user's crushes if not already added
    await User.findByIdAndUpdate(currentUserId, {
      $push: { crushes: selectedUserId },
    });

    // Create persistent notification for the profile like
    try {
      await createNotificationWithCaps({
        userId: selectedUserId,
        type: "profile_like",
        title: "Someone wants to stay in touch",
        message: `${currentUser.name || "A user"} wants to stay in touch with you`,
        actorId: currentUserId,
        actorName: currentUser.name,
        actorImage: currentUser.profileImages?.[0] || null,
      });
    } catch (notifError) {
      console.error("Error creating profile like notification:", notifError);
    }

    return res.status(200).json({ message: "Profile liked successfully." });
  } catch (error) {
    console.error("Error liking profile:", error); // Log the actual error to the server console
    return res
      .status(500)
      .json({ message: "Failed to like profile", error: error.message });
  }
});

// get the people that liked your profile

app.get("/recievedLikes/:userId/info", async (req, res) => {
  try {
    const { userId } = req.params;

    // Retrieve the current user with their interests for mutual matching
    const currentUser = await User.findById(userId)
      .select("recievedLikes profileDislikes interests location")
      .lean();

    if (!currentUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Extract the IDs of the current user's disliked profiles
    const deslikedProfileId = (currentUser.profileDislikes || []).map(
      (profileDeslike) => profileDeslike.toString(),
    );

    // Find users in the recievedLikes array but exclude disliked profiles
    const recievedLikesArray = await User.find({
      _id: { $in: currentUser.recievedLikes, $nin: deslikedProfileId },
    })
      .select(
        "_id name age gender profileImages location interests verified lastActiveAt updatedAt",
      )
      .lean();

    // Add mutual interests and format response for premium features
    const formattedLikes = recievedLikesArray.map((user) => {
      const userInterests = user.interests || [];
      const currentUserInterests = currentUser.interests || [];
      const mutualInterests = userInterests.filter((interest) =>
        currentUserInterests.includes(interest),
      );

      return {
        ...user,
        mutualInterests,
        mutualInterestsCount: mutualInterests.length,
      };
    });

    // Fetch pending Super Flirts for this user
    const pendingSuperFlirts = await SuperFlirt.find({
      receiverId: userId,
      status: "pending",
    }).lean();

    const superFlirtSenderIds = pendingSuperFlirts.map((sf) => sf.senderId);
    const superFlirtSenders = await User.find({
      _id: { $in: superFlirtSenderIds },
    })
      .select("_id name age gender profileImages location verified")
      .lean();

    const senderMap = {};
    superFlirtSenders.forEach((s) => {
      senderMap[s._id.toString()] = s;
    });

    const superFlirtsFormatted = pendingSuperFlirts.map((sf) => {
      const sender = senderMap[sf.senderId.toString()] || {};
      return {
        superFlirtId: sf._id,
        senderId: sf.senderId,
        name: sender.name || "Unknown",
        photo: sender.profileImages?.[0] || null,
        age: sender.age,
        gender: sender.gender,
        location: sender.location,
        verified: sender.verified,
        message: sf.message,
        createdAt: sf.createdAt,
      };
    });

    return res.status(200).json({
      likes: formattedLikes,
      super_flirts: superFlirtsFormatted,
    });
  } catch (error) {
    console.error("Error fetching received likes:", error);
    res.status(500).json({ message: "Failed to retrieve the received likes" });
  }
});

// Super Wave - Premium feature to get noticed by nearby users
// Also triggers the like functionality (adds to recievedLikes and crushes)
app.post("/super-wave", async (req, res) => {
  try {
    const { senderId, receiverId } = req.body;

    if (!senderId || !receiverId) {
      return res
        .status(400)
        .json({ message: "senderId and receiverId are required" });
    }

    const sender = await User.findById(senderId)
      .select("name profileImages crushes coAttendees")
      .lean();
    const receiver = await User.findById(receiverId)
      .select("pushToken recievedLikes")
      .lean();

    // Gate: must have attended at least one shared activity (coAttendees)
    if (
      sender &&
      !(sender.coAttendees || []).some(
        (id) => id.toString() === receiverId.toString(),
      )
    ) {
      return res.status(403).json({
        message:
          "You need to have attended at least 1 activity with this person before you can connect with them.",
      });
    }

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if already liked to avoid duplicates
    const alreadyLiked = receiver.recievedLikes?.some(
      (id) => id.toString() === senderId.toString(),
    );

    if (!alreadyLiked) {
      // Add sender to receiver's recievedLikes (like functionality)
      await User.findByIdAndUpdate(receiverId, {
        $addToSet: { recievedLikes: senderId },
      });

      // Add receiver to sender's crushes
      await User.findByIdAndUpdate(senderId, {
        $addToSet: { crushes: receiverId },
      });

      // Create profile_like notification (in-app only if no push token; never fail the wave)
      try {
        await createNotificationWithCaps({
          userId: receiverId,
          type: "profile_like",
          title: "Someone wants to connect",
          message: `${sender.name || "Someone"} sent you a Super Wave and likes your profile`,
          actorId: senderId,
          actorName: sender.name,
          actorImage: sender.profileImages?.[0] || null,
        });
      } catch (notifErr) {
        console.error(
          "[Super Wave] profile_like notification failed (wave still succeeded):",
          notifErr?.message || notifErr,
        );
      }
    }

    // Create super_wave notification (in-app only if no push token; never fail the wave)
    try {
      await createNotificationWithCaps({
        userId: receiverId,
        type: "super_wave",
        title: "Someone waved at you!",
        message: `${sender.name || "Someone"} sent you a Super Wave`,
        actorId: senderId,
        actorName: sender.name,
        actorImage: sender.profileImages?.[0] || null,
      });
    } catch (notifErr) {
      console.error(
        "[Super Wave] super_wave notification failed (wave still succeeded):",
        notifErr?.message || notifErr,
      );
    }

    console.log(
      `Super Wave sent from ${senderId} to ${receiverId}${alreadyLiked ? " (already liked)" : " (like added)"}`,
    );
    res.status(200).json({ message: "Super Wave sent successfully" });
  } catch (error) {
    console.error("Error sending super wave:", error);
    res.status(500).json({ message: "Failed to send Super Wave" });
  }
});

// Super Flirt - send a personalised message with a like
const SUPER_FLIRT_DAILY_CAP = 5;

app.post("/super-flirts", async (req, res) => {
  try {
    const { senderId, receiverId, message } = req.body;

    if (!senderId || !receiverId) {
      return res
        .status(400)
        .json({ message: "senderId and receiverId are required" });
    }

    if (
      !message ||
      typeof message !== "string" ||
      message.trim().length === 0
    ) {
      return res
        .status(400)
        .json({ message: "message is required and cannot be empty" });
    }

    if (message.length > 150) {
      return res
        .status(400)
        .json({ message: "message must be 150 characters or fewer" });
    }

    const now = new Date();
    const startOfTodayUTC = new Date(
      Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate(),
        0,
        0,
        0,
        0,
      ),
    );
    const sentToday = await SuperFlirt.countDocuments({
      senderId,
      createdAt: { $gte: startOfTodayUTC },
    });
    if (sentToday >= SUPER_FLIRT_DAILY_CAP) {
      return res.status(429).json({
        message: `Daily Super Flirt limit reached (${SUPER_FLIRT_DAILY_CAP} per day). Try again tomorrow.`,
      });
    }

    const sender = await User.findById(senderId)
      .select("name profileImages crushes")
      .lean();
    const receiver = await User.findById(receiverId)
      .select("pushToken preferredLanguage recievedLikes")
      .lean();

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    const superFlirt = new SuperFlirt({
      senderId,
      receiverId,
      message: message.trim(),
    });
    await superFlirt.save();

    const alreadyLiked = receiver.recievedLikes?.some(
      (id) => id.toString() === senderId.toString(),
    );

    if (!alreadyLiked) {
      await User.findByIdAndUpdate(receiverId, {
        $addToSet: { recievedLikes: senderId },
      });
      await User.findByIdAndUpdate(senderId, {
        $addToSet: { crushes: receiverId },
      });
    }

    try {
      const sfStrings = getStrings(
        receiver.preferredLanguage,
      ).superFlirtReceived;
      const sfTitle = interpolate(sfStrings.title, {
        name: sender.name || "Someone",
      });
      const sfBody = interpolate(sfStrings.body, {
        name: sender.name || "Someone",
      });

      await createNotificationWithCaps({
        userId: receiverId,
        type: "super_flirt",
        title: sfTitle,
        message: sfBody,
        actorId: senderId,
        actorName: sender.name,
        actorImage: sender.profileImages?.[0] || null,
      });

      if (receiver.pushToken) {
        await sendNotification(receiver.pushToken, sfTitle, sfBody, {
          type: "super_flirt",
          actorId: senderId.toString(),
        });
      }
    } catch (notifErr) {
      console.error(
        "[Super Flirt] notification failed:",
        notifErr?.message || notifErr,
      );
    }

    console.log(`Super Flirt sent from ${senderId} to ${receiverId}`);
    res
      .status(200)
      .json({
        message: "Super Flirt sent successfully",
        superFlirtId: superFlirt._id,
      });
  } catch (error) {
    console.error("Error sending super flirt:", error);
    res.status(500).json({ message: "Failed to send Super Flirt" });
  }
});

// Super Flirt - match back
app.post("/super-flirts/:id/match", async (req, res) => {
  try {
    const { id } = req.params;
    const { currentUserId } = req.body;

    if (!currentUserId) {
      return res.status(400).json({ message: "currentUserId is required" });
    }

    const superFlirt = await SuperFlirt.findById(id);
    if (!superFlirt) {
      return res.status(404).json({ message: "Super Flirt not found" });
    }

    if (superFlirt.receiverId.toString() !== currentUserId.toString()) {
      return res
        .status(403)
        .json({ message: "Not authorized to match this Super Flirt" });
    }

    if (superFlirt.status !== "pending") {
      return res
        .status(400)
        .json({ message: "Super Flirt has already been actioned" });
    }

    superFlirt.status = "matched";
    await superFlirt.save();

    const senderId = superFlirt.senderId.toString();

    // Create match — same logic as POST /create-match
    await User.findByIdAndUpdate(currentUserId, {
      $push: { Matches: senderId },
      $pull: { recievedLikes: senderId },
    });
    await User.findByIdAndUpdate(senderId, {
      $push: { Matches: currentUserId },
      $pull: { recievedLikes: currentUserId },
    });

    // Write the Super Flirt message as the opening chat message
    const openerMessage = new Chat({
      senderId: senderId,
      receiverId: currentUserId,
      message: superFlirt.message,
      type: "super_flirt_opener",
      timestamp: new Date(),
    });
    await openerMessage.save();

    // Send match push notification to the original sender
    const senderUser = await User.findById(senderId)
      .select("pushToken preferredLanguage")
      .lean();
    if (senderUser?.pushToken) {
      try {
        const sfMatch = getStrings(
          senderUser.preferredLanguage,
        ).superFlirtMatched;
        await sendNotification(
          senderUser.pushToken,
          sfMatch.title,
          sfMatch.body,
          {
            type: "super_flirt_match",
            actorId: currentUserId.toString(),
          },
        );
      } catch (pushErr) {
        console.error(
          "[Super Flirt Match] push notification failed:",
          pushErr?.message || pushErr,
        );
      }
    }

    console.log(`Super Flirt ${id} matched by ${currentUserId}`);
    res.status(200).json({ message: "Matched successfully", senderId });
  } catch (error) {
    console.error("Error matching super flirt:", error);
    res.status(500).json({ message: "Failed to match Super Flirt" });
  }
});

// Super Flirt - pass
app.post("/super-flirts/:id/pass", async (req, res) => {
  try {
    const { id } = req.params;
    const { currentUserId } = req.body;

    if (!currentUserId) {
      return res.status(400).json({ message: "currentUserId is required" });
    }

    const superFlirt = await SuperFlirt.findById(id);
    if (!superFlirt) {
      return res.status(404).json({ message: "Super Flirt not found" });
    }

    if (superFlirt.receiverId.toString() !== currentUserId.toString()) {
      return res
        .status(403)
        .json({ message: "Not authorized to pass this Super Flirt" });
    }

    if (superFlirt.status !== "pending") {
      return res
        .status(400)
        .json({ message: "Super Flirt has already been actioned" });
    }

    superFlirt.status = "passed";
    await superFlirt.save();

    // Remove sender from receiver's recievedLikes
    await User.findByIdAndUpdate(currentUserId, {
      $pull: { recievedLikes: superFlirt.senderId },
    });

    console.log(`Super Flirt ${id} passed by ${currentUserId}`);
    res.status(200).json({ message: "Super Flirt passed" });
  } catch (error) {
    console.error("Error passing super flirt:", error);
    res.status(500).json({ message: "Failed to pass Super Flirt" });
  }
});

// ─── Priority Boost endpoints ────────────────────────────────────────────────

const BOOST_CREDITS_PER_CYCLE = 4;
const BOOST_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

// GET /boosts/status?userId=...
app.get("/boosts/status", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Valid userId is required" });
    }

    const user = await User.findById(userId).select("boostCredits").lean();
    if (!user) return res.status(404).json({ message: "User not found" });

    const activeBoost = await Boost.findOne({
      userId,
      status: "active",
    }).lean();

    res.status(200).json({
      active: !!activeBoost,
      expires_at: activeBoost ? activeBoost.expiresAt : null,
      credits_remaining: user.boostCredits?.remaining ?? 0,
      credits_reset_at: user.boostCredits?.resetAt ?? null,
      total_credits_this_cycle: BOOST_CREDITS_PER_CYCLE,
    });
  } catch (error) {
    console.error("Error fetching boost status:", error);
    res.status(500).json({ message: "Failed to fetch boost status" });
  }
});

// POST /boosts/activate  { userId, hasAccess }
app.post("/boosts/activate", async (req, res) => {
  try {
    const { userId, hasAccess } = req.body;
    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Valid userId is required" });
    }

    if (!hasAccess) {
      return res
        .status(403)
        .json({ message: "Priority Boost requires a Flirt Gold subscription" });
    }

    // Enforce one active boost at a time
    const existingActive = await Boost.findOne({ userId, status: "active" });
    if (existingActive) {
      return res
        .status(409)
        .json({
          message: "You already have an active Priority Boost",
          expires_at: existingActive.expiresAt,
        });
    }

    const user = await User.findById(userId)
      .select("boostCredits pushToken preferredLanguage name")
      .lean();
    if (!user) return res.status(404).json({ message: "User not found" });

    const creditsRemaining = user.boostCredits?.remaining ?? 0;
    if (creditsRemaining <= 0) {
      return res.status(403).json({
        message: "No Boost credits remaining this month",
        credits_reset_at: user.boostCredits?.resetAt ?? null,
      });
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + BOOST_DURATION_MS);

    const boost = new Boost({ userId, activatedAt: now, expiresAt });
    await boost.save();

    // Set priority = 1 so this user appears first in discovery
    await User.findByIdAndUpdate(userId, {
      priority: 1,
      $inc: { "boostCredits.remaining": -1 },
    });

    // Immediate activation push notification
    const boostActivatedStr = getStrings(user.preferredLanguage).boostActivated;
    if (user.pushToken) {
      try {
        await sendNotification(
          user.pushToken,
          boostActivatedStr.title,
          boostActivatedStr.body,
          {
            type: "boost_activated",
          },
        );
      } catch (notifErr) {
        console.error(
          "[Boost] Activation notification failed:",
          notifErr?.message,
        );
      }
    }

    // Store in-app notification
    try {
      await createNotificationWithCaps({
        userId,
        type: "boost_activated",
        title: boostActivatedStr.title,
        message: boostActivatedStr.body,
      });
    } catch (notifErr) {
      console.error("[Boost] In-app notification failed:", notifErr?.message);
    }

    console.log(
      `[Boost] Activated for user ${userId}, expires ${expiresAt.toISOString()}`,
    );
    res.status(200).json({
      message: "Priority Boost activated",
      boost_id: boost._id,
      expires_at: expiresAt,
      credits_remaining: creditsRemaining - 1,
    });
  } catch (error) {
    console.error("Error activating boost:", error);
    res.status(500).json({ message: "Failed to activate Priority Boost" });
  }
});

// POST /boosts/reset-credits  { userId }  — called client-side after Gold subscription purchase/renewal
app.post("/boosts/reset-credits", async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Valid userId is required" });
    }

    const resetAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const user = await User.findByIdAndUpdate(
      userId,
      { boostCredits: { remaining: BOOST_CREDITS_PER_CYCLE, resetAt } },
      { new: true },
    ).select("pushToken preferredLanguage");

    if (!user) return res.status(404).json({ message: "User not found" });

    const boostResetStr = getStrings(user.preferredLanguage).boostCreditsReset;

    if (user.pushToken) {
      try {
        await sendNotification(
          user.pushToken,
          boostResetStr.title,
          boostResetStr.body,
          {
            type: "boost_credits_reset",
          },
        );
      } catch (notifErr) {
        console.error(
          "[Boost] Credits reset notification failed:",
          notifErr?.message,
        );
      }
    }

    try {
      await createNotificationWithCaps({
        userId,
        type: "boost_credits_reset",
        title: boostResetStr.title,
        message: boostResetStr.body,
      });
    } catch (notifErr) {
      console.error(
        "[Boost] Credits reset in-app notification failed:",
        notifErr?.message,
      );
    }

    console.log(`[Boost] Credits reset for user ${userId}`);
    res
      .status(200)
      .json({
        message: "Boost credits reset",
        credits_remaining: BOOST_CREDITS_PER_CYCLE,
        credits_reset_at: resetAt,
      });
  } catch (error) {
    console.error("Error resetting boost credits:", error);
    res.status(500).json({ message: "Failed to reset boost credits" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────

app.post("/create-match", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    //update the selected users recieved  likes and matches
    await User.findByIdAndUpdate(selectedUserId, {
      $push: { Matches: currentUserId },
      $pull: { recievedLikes: currentUserId },
    });

    //update the current users  reived likes and matches
    await User.findByIdAndUpdate(currentUserId, {
      $push: { Matches: selectedUserId },
      $pull: { recievedLikes: selectedUserId },
    });

    // Fetch the selected user's expo push token
    const selectedUser = await User.findById(selectedUserId).select(
      "pushToken preferredLanguage",
    );

    // Only send notification if the expoPushToken is available
    if (selectedUser && selectedUser.pushToken) {
      const s = getStrings(selectedUser.preferredLanguage).newMatch;
      await sendNotification(selectedUser.pushToken, s.title, s.body, {
        type: "new_match",
        actorId: currentUserId.toString(),
      });
    }
    res.sendStatus(200);
    console.log("new match ");
  } catch (error) {
    res.status(500).json({ message: "failed to match the users", error });
  }
});

// fetch the users you matched with

app.get("/matches/:userId/info", async (req, res) => {
  try {
    const { userId } = req.params;

    // Find the user by userId
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Get the user's match IDs
    const matchIds = user.Matches;

    // Fetch matches based on match IDs
    const matches = await User.find({ _id: { $in: matchIds } });

    // Filter out matches that have the current user in their blockedBy array
    const filteredMatches = matches.filter(
      (match) => !match.blockedBy.includes(userId),
    );

    // Populate each match with the latest message details and unread count
    const updatedMatches = await Promise.all(
      filteredMatches.map(async (match) => {
        const latestMessage = await fetchLatestMessage(userId, match._id);

        // Find the conversation for the current match
        const conversation = user.conversations.find(
          (conv) => conv.receiverId.toString() === match._id.toString(),
        );

        return {
          ...match.toObject(),
          lastMessage: latestMessage?.message || "No messages",
          timestamp: latestMessage?.timestamp || null,
          typing: latestMessage?.typing || false,
          unreadCount: conversation ? conversation.unreadMessagesCount : 0, // Get unread count from conversations
        };
      }),
    );

    // Sort matches by the timestamp of the latest message
    const sortedMatches = updatedMatches.sort((a, b) => {
      const aTime = a.timestamp ? new Date(a.timestamp) : 0; // Convert to date object
      const bTime = b.timestamp ? new Date(b.timestamp) : 0; // Convert to date object
      return bTime - aTime; // Sort in descending order
    });

    // Return the filtered and updated matches with latest messages
    res.status(200).json(sortedMatches);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to retrieve matches and latest messages." });
  }
});

// Helper function to fetch the latest message between two users
const fetchLatestMessage = async (userId, matchId) => {
  // Find the latest message between the users
  const latestMessage = await Message.findOne({
    $or: [
      { senderId: userId, receiverId: matchId },
      { senderId: matchId, receiverId: userId },
    ],
  })
    .sort({ timestamp: -1 }) // Sort by timestamp, assuming it's the field you're using
    .lean();

  return latestMessage || {};
};

// Delete inappropriate image from user profile
app.delete("/users/:userId/images", async (req, res) => {
  try {
    const { userId } = req.params;
    const { imageUrl, reason } = req.body;

    // Validate input
    if (!userId || !imageUrl) {
      return res.status(400).json({ message: "Missing required parameters" });
    }

    // Find the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if the image exists in the user's profile images
    if (!user.profileImages.includes(imageUrl)) {
      return res
        .status(404)
        .json({ message: "Image not found in user profile" });
    }

    // Remove the image from the profileImages array
    user.profileImages = user.profileImages.filter((img) => img !== imageUrl);
    await user.save();

    let r2Warning = null;
    const key = keyFromPublicUrl(imageUrl);
    if (key) {
      try {
        await deleteObjectFromR2(key);
      } catch (e) {
        r2Warning = `Failed to delete image from R2 (key: ${key})`;
        console.error("[R2 delete] Failed to delete object:", {
          userId,
          key,
          error: e?.message || e,
        });
      }
    }

    // Log the moderation action
    console.log(
      `Image deleted from user ${userId} for reason: ${
        reason || "No reason provided"
      }`,
    );

    return res.status(200).json({
      message: "Image deleted successfully",
      remainingImages: user.profileImages.length,
      warning: r2Warning || undefined,
    });
  } catch (error) {
    console.error("Error deleting image:", error);
    return res.status(500).json({ message: "Failed to delete image" });
  }
});

app.get("/messages/:senderId/:receiverId", async (req, res) => {
  const { senderId, receiverId } = req.params;
  const { skip = 0, limit = 20 } = req.query;
  try {
    // Fetch messages based on senderId and receiverId with pagination
    const messages = await Message.find({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId },
      ],
    })
      .sort({ timestamp: -1 }) // Sort messages by timestamp in descending order
      .skip(Number(skip)) // Skip the first `skip` messages
      .limit(Number(limit)); // Limit to `limit` messages

    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: "Error fetching messages" });
  }
});

// API endpoint to save multiple messages
app.post("/messages/save", async (req, res) => {
  try {
    const messages = req.body;

    // Create an array of Chat message instances
    const chatMessages = messages.map((msg) => ({
      senderId: msg.senderId,
      receiverId: msg.receiverId,
      message: msg.message,
      type: msg.type || "text",
      image: msg.image, // Include the image field
      timestamp: new Date(msg.timestamp),
    }));

    // Save all messages to the database
    const savedMessages = await Chat.insertMany(chatMessages);

    res.status(201).json({
      success: true,
      message: "Messages saved successfully",
      data: savedMessages,
    });
  } catch (error) {
    console.error("Error saving messages:", error);
    res.status(500).json({
      success: false,
      message: "Error saving messages",
      error: error.message,
    });
  }
});

app.put("/push-notification-token/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { pushToken, language } = req.body;

    if (!pushToken && !language) {
      console.log(
        "🔔 [PUSH TOKEN API] ❌ No pushToken or language provided in request body",
      );
      return res
        .status(400)
        .json({ message: "pushToken or language is required" });
    }

    const supportedLanguages = ["en", "es", "ja", "de", "fr"];
    const updateData = {};
    if (pushToken) updateData.pushToken = pushToken;
    if (language && supportedLanguages.includes(language)) {
      updateData.preferredLanguage = language;
    }

    const user = await User.findByIdAndUpdate(userId, updateData, {
      new: true,
    });

    if (!user) {
      console.log("🔔 [PUSH TOKEN API] ❌ User not found:", userId);
      return res.status(404).json({ message: "user not found" });
    }

    return res
      .status(200)
      .json({
        message: "user pushToken updated successfully",
        savedToken: user.pushToken,
      });
  } catch (error) {
    console.error("🔔 [PUSH TOKEN API] ❌ ERROR:", error.message);
    res
      .status(500)
      .json({
        message: "Error updating users push token ",
        error: error.message,
      });
  }
});

// Migration endpoint: Set all users without platform field to "unknown"
app.post("/admin/migrate-user-platforms", async (req, res) => {
  try {
    const result = await User.updateMany(
      { platform: { $exists: false } },
      { $set: { platform: "unknown" } },
    );
    res.json({
      message: "Migration completed",
      updated: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error migrating user platforms:", error);
    res.status(500).json({ error: error.message });
  }
});

// add users location
app.post("/user/:userId/update-location", async (req, res) => {
  try {
    const { userId } = req.params;
    const { longitude, latitude } = req.body;

    // Parse and validate coordinates
    const parsedLong = parseFloat(longitude);
    const parsedLat = parseFloat(latitude);

    if (isNaN(parsedLong) || isNaN(parsedLat)) {
      return res.status(400).json({ error: "Invalid coordinates format" });
    }

    // Validate coordinate bounds
    if (Math.abs(parsedLat) > 90 || Math.abs(parsedLong) > 180) {
      return res.status(400).json({ error: "Coordinates out of bounds" });
    }

    // Validate non-zero coordinates
    if (parsedLong === 0 && parsedLat === 0) {
      return res.status(400).json({ error: "Invalid zero coordinates" });
    }

    // Update user's location
    const user = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          location: {
            type: "Point",
            coordinates: [parsedLong, parsedLat], // MongoDB expects [longitude, latitude]
          },
        },
      },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update the user's country based on coordinates
    try {
      const countryResult = await updateUserCountry(userId);

      return res.status(200).json({
        message: "Location and country updated successfully",
        user,
        country: countryResult.country,
      });
    } catch (countryError) {
      console.error("❌ Error updating country:", countryError);
      // Return detailed error information
      return res.status(200).json({
        message: "Location updated successfully, but country update failed",
        user,
        countryError: {
          message: countryError.message,
          details: countryError.stack,
        },
      });
    }
  } catch (error) {
    console.error("❌ Error updating user's location:", error);
    return res.status(500).json({
      message: "Error updating user's location",
      error: error.message,
      stack: error.stack,
    });
  }
});

// fetch users that are close to each other due to location

app.get("/nearby-users", async (req, res) => {
  try {
    const { longitude, latitude, maxDistance, userId, limit } = req.query;

    if (!longitude || !latitude || !maxDistance) {
      return res
        .status(400)
        .json({ error: "Longitude, latitude, and maxDistance are required" });
    }

    // Parse coordinates and distance
    const parsedLong = parseFloat(longitude);
    const parsedLat = parseFloat(latitude);
    const parsedMaxDistance = parseInt(maxDistance) || 5000; // Default to 5km if not valid

    // Validate parsed coordinates
    if (isNaN(parsedLong) || isNaN(parsedLat)) {
      return res.status(400).json({ error: "Invalid coordinates format" });
    }

    // Fetch user data upfront (like /profiles endpoint) - optimized for performance
    let excludedIds = [];
    let genderFilter = null;

    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const currentUser = await User.findById(userId)
        .select("gender blockedBy")
        .lean();

      if (currentUser) {
        // Exclude current user
        excludedIds.push(new mongoose.Types.ObjectId(userId));

        // Exclude users who have blocked the current user
        if (currentUser.blockedBy?.length > 0) {
          excludedIds = excludedIds.concat(
            currentUser.blockedBy.map((id) => new mongoose.Types.ObjectId(id)),
          );
        }

        // iOS Cuddles specific: Filter by opposite gender (dating app)
        if (currentUser.gender === "male") {
          genderFilter = "female";
        } else if (currentUser.gender === "female") {
          genderFilter = "male";
        }
      }
    }

    // Optimized query filter - all exclusions included upfront (no $lookup needed)
    // Never show iOS platform users on find people nearby (iOS app shows only android/unknown)
    const queryFilter = {
      profileImages: { $exists: true, $ne: [] },
      "location.coordinates": { $exists: true, $ne: [0, 0] },
      flagged: { $ne: true },
      platform: { $ne: "ios" },
      ...(excludedIds.length > 0 && { _id: { $nin: excludedIds } }),
      ...(genderFilter && { gender: genderFilter }), // iOS Cuddles: opposite gender only
    };

    // Simple aggregation pipeline - no expensive $lookup
    const nearbyUsers = await User.aggregate([
      {
        $geoNear: {
          near: {
            type: "Point",
            coordinates: [parsedLong, parsedLat],
          },
          distanceField: "distance",
          maxDistance: parsedMaxDistance,
          spherical: true,
          query: queryFilter,
          distanceMultiplier: 0.001, // Convert to kilometers
        },
      },
      {
        $project: {
          _id: 1,
          name: 1,
          age: 1,
          gender: 1,
          profileImages: { $slice: ["$profileImages", 1] }, // Only first image
          distance: 1,
          verified: 1,
          description: 1,
        },
      },
      {
        $limit: Math.min(parseInt(limit) || 20, 50), // Default 20, max 50
      },
    ]).option({ maxTimeMS: 5000 });

    res.status(200).json({
      message:
        nearbyUsers.length > 0 ? "Nearby users found" : "No users found nearby",
      users: nearbyUsers,
    });
  } catch (error) {
    console.error("Error finding nearby users:", error);
    res
      .status(500)
      .json({ error: "Internal server error", details: error.message });
  }
});

// Your delete endpoint

app.delete("/users/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format." });
    }

    const objectId = new mongoose.Types.ObjectId(userId);

    const userToDelete = await User.findById(objectId).lean();

    if (!userToDelete) {
      return res.status(404).json({ message: "User not found" });
    }

    const urls = [];
    if (Array.isArray(userToDelete.profileImages)) {
      urls.push(...userToDelete.profileImages);
    }
    const selfieUrl = userToDelete.profileVerification?.selfieUrl;
    if (selfieUrl) urls.push(selfieUrl);

    const keys = urls.map((u) => keyFromPublicUrl(u)).filter(Boolean);

    const failedR2Deletes = [];
    if (keys.length > 0) {
      const results = await Promise.allSettled(
        keys.map((key) => deleteObjectFromR2(key)),
      );
      results.forEach((r, idx) => {
        if (r.status === "rejected") {
          failedR2Deletes.push({
            key: keys[idx],
            error: r.reason?.message || String(r.reason),
          });
          console.error("[R2 delete] Failed to delete object:", {
            userId,
            key: keys[idx],
            error: r.reason?.message || r.reason,
          });
        }
      });
    }

    const deletedUser = await User.findByIdAndDelete(objectId);

    if (!deletedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Remove user from all event participants so they no longer appear in any activities
    await Event.updateMany(
      { "participants.userId": objectId },
      { $pull: { participants: { userId: objectId } } },
    );

    return res.status(200).json({
      message: "User deleted successfully",
      warning:
        failedR2Deletes.length > 0
          ? "Some R2 objects could not be deleted"
          : undefined,
      failedR2Deletes: failedR2Deletes.length > 0 ? failedR2Deletes : undefined,
    });
  } catch (error) {
    console.error("Error deleting user:", error);
    return res
      .status(500)
      .json({ message: "Error deleting user", error: error.message });
  }
});

// Endpoint to update profile image
app.put(
  "/update-profile-image/:userId",
  imageUploadSingle,
  async (req, res) => {
    const { userId } = req.params;

    try {
      // Check if file is uploaded
      if (!req.file) {
        console.log("image file not uploaded");
        return res.status(400).json({ message: "No image file uploaded" });
      }

      let normalized;
      try {
        normalized = await normalizeProfileImageToJpeg(
          req.file.buffer,
          req.file.mimetype,
        );
      } catch (e) {
        return res.status(400).json({ message: e?.message || "Invalid image" });
      }

      const key = buildUserImageKey({
        userId,
        mimetype: normalized.contentType,
        originalname: req.file.originalname,
        extOverride: normalized.extension,
      });

      const { url: imageUrl } = await uploadImageBufferToR2({
        buffer: normalized.buffer,
        contentType: normalized.contentType,
        key,
      });

      console.log(userId, imageUrl);

      // Update user profile image in the database
      const updatedUser = await User.findOneAndUpdate(
        { _id: userId },
        { $set: { "profileImages.0": imageUrl } }, // Replace the first image
        { new: true },
      );

      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }

      res.status(200).json({
        message: "Profile image updated successfully",
        profileImages: updatedUser.profileImages,
      });
    } catch (error) {
      console.error("Error updating profile image:", error);
      res.status(500).json({ message: "Server error", error });
    }
  },
);

app.put("/change-username/:userId", async (req, res) => {
  const { userId } = req.params;
  const { newUsername } = req.body;
  try {
    // Find the user by ID and update the username
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update the username
    user.name = newUsername;
    await user.save();

    return res.status(200).json({ message: "Username changed successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/cuddles/request-otp", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
    const otpExpires = Date.now() + 60000; // expires in 1 minute

    // Save OTP and expiration in the user's document
    user.otp = { code: otp, expires: otpExpires };
    await user.save();

    // Send OTP to email
    try {
      const emailResult = await transporter.sendMail({
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP code is ${otp}. It is valid for 1 minute.`,
      });

      console.log("Email sent successfully:", emailResult.messageId);
      res.status(200).json({
        message: "OTP sent to your email.",
        emailSent: true,
        messageId: emailResult.messageId,
      });
    } catch (emailError) {
      console.error("Failed to send email:", emailError);
      // Still save the OTP but notify about email delivery failure
      res.status(200).json({
        message: "OTP generated but email delivery failed. Please try again.",
        emailSent: false,
        error: emailError.message,
      });
    }
  } catch (error) {
    console.error("Error in requesting OTP:", error);
    res.status(500).json({ message: "An error occurred." });
  }
});

app.post("/cuddles/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Verify OTP
    if (!user.otp || user.otp.code !== otp) {
      return res.status(400).json({ message: "Invalid OTP." });
    }

    if (Date.now() > user.otp.expires) {
      return res.status(400).json({ message: "OTP has expired." });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the OTP
    user.password = hashedPassword;
    user.otp = undefined; // Clear OTP
    await user.save();

    res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    console.error("Error in changing password:", error);
    res.status(500).json({ message: "An error occurred." });
  }
});

app.post("/addToCrushes", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and the selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId);

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user already has the selected user in their crushes
    const alreadyCrush = currentUser.crushes.some((crush) =>
      crush.equals(selectedUser._id),
    );

    if (alreadyCrush) {
      return res
        .status(400)
        .json({ message: "You have already added this user to your crushes." });
    }

    // Add the selected user's ObjectId to the current user's crushes
    await User.findByIdAndUpdate(currentUserId, {
      $push: { crushes: selectedUser._id }, // Adding the ObjectId of the selected user
    });

    return res
      .status(200)
      .json({ message: "User added to crushes successfully." });
  } catch (error) {
    console.error("Error adding user to crushes:", error); // Log the error for debugging
    return res
      .status(500)
      .json({ message: "Failed to add user to crushes", error: error.message });
  }
});

app.post("/addToDislikes", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and the selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId);

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user already has the selected user in their dislikes
    const alreadyDisliked = currentUser.profileDislikes.some(
      (profileDislikes) => profileDislikes.equals(selectedUser._id),
    );

    if (alreadyDisliked) {
      return res.status(400).json({
        message: "You have already added this user to your dislikes.",
      });
    }

    // Add the selected user's ObjectId to the current user's dislikes
    await User.findByIdAndUpdate(currentUserId, {
      $push: { profileDislikes: selectedUser._id },
    });

    return res
      .status(200)
      .json({ message: "User added to dislikes successfully." });
  } catch (error) {
    console.error("Error adding user to dislikes:", error);
    return res.status(500).json({
      message: "Failed to add user to dislikes",
      error: error.message,
    });
  }
});

app.post("/blockUser", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;
    // Ensure both IDs are provided
    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required." });
    }

    // Find the current user and the selected user
    const currentUser = await User.findById(currentUserId);
    const selectedUser = await User.findById(selectedUserId);

    if (!currentUser || !selectedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if the current user already has the selected user in their dislikes
    const alreadyBlocked = selectedUser.blockedBy.some((blockedBy) =>
      blockedBy.equals(currentUser),
    );

    // Add the selected user's ObjectId to the current user's dislikes
    await User.findByIdAndUpdate(selectedUser, {
      $push: { blockedBy: currentUser._id },
    });

    return res
      .status(200)
      .json({ message: "User added to blocked successfully." });
  } catch (error) {}
});

app.post("/report", async (req, res) => {
  const { reporterId, reportedUserId, reportedEventId, reason, message } =
    req.body;

  if (!reporterId || !message) {
    return res
      .status(400)
      .json({ error: "reporterId and message are required." });
  }

  if (!reportedUserId && !reportedEventId) {
    return res
      .status(400)
      .json({ error: "reportedUserId or reportedEventId is required." });
  }

  try {
    const reporter = await User.findById(reporterId);
    if (!reporter) {
      return res.status(404).json({ error: "Reporter not found." });
    }

    if (reportedUserId) {
      const reportedUser = await User.findById(reportedUserId);
      if (!reportedUser) {
        return res.status(404).json({ error: "Reported user not found." });
      }
    }

    if (reportedEventId) {
      const reportedEvent = await Event.findById(reportedEventId);
      if (!reportedEvent) {
        return res.status(404).json({ error: "Reported event not found." });
      }
    }

    const reportData = { reporterId, message };
    if (reportedUserId) reportData.reportedUserId = reportedUserId;
    if (reportedEventId) reportData.reportedEventId = reportedEventId;
    if (reason) reportData.reason = reason;

    const report = new Report(reportData);
    await report.save();

    const target = reportedUserId
      ? `user with ID ${reportedUserId}`
      : `event with ID ${reportedEventId}`;
    const reasonText = reason ? `\nReason: ${reason}` : "";

    try {
      await transporter.sendMail({
        from: "cuddlesquery@gmail.com",
        to: "cuddlesquery@gmail.com",
        subject: "New Report",
        text: `User with ID ${reporterId} reported ${target}.${reasonText}\n\nMessage: ${message}`,
      });
    } catch (mailError) {
      console.error("Report saved but email notification failed:", mailError);
    }

    res.status(201).json({ message: "Report submitted successfully." });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ error: "An error occurred while submitting the report." });
  }
});

// Get all reports with pagination and status filter
app.get("/report", async (req, res) => {
  try {
    const { page = 1, limit = 10, status = "all" } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build query based on status
    const query = status === "all" ? {} : { status };

    // Get reports with pagination
    const reports = await Report.find(query)
      .populate("reporterId", "name email")
      .populate("reportedUserId", "name email")
      .sort({ date: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const total = await Report.countDocuments(query);

    res.status(200).json({
      reports,
      total,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching reports." });
  }
});

// Get a specific report by ID
app.get("/report/:id", async (req, res) => {
  try {
    const report = await Report.findById(req.params.id)
      .populate("reporterId", "name email")
      .populate("reportedUserId", "name email");

    if (!report) {
      return res.status(404).json({ error: "Report not found." });
    }

    res.status(200).json(report);
  } catch (error) {
    console.error("Error fetching report:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching the report." });
  }
});

// Resolve a report
app.put("/report/:id/resolve", async (req, res) => {
  try {
    const { action, notes } = req.body;
    const reportId = req.params.id;

    if (!action) {
      return res.status(400).json({ error: "Action is required." });
    }

    const report = await Report.findById(reportId);
    if (!report) {
      return res.status(404).json({ error: "Report not found." });
    }

    // Update report status
    report.status = "resolved";
    report.action = action;
    report.notes = notes;
    report.resolvedAt = new Date();
    await report.save();

    // If action is 'block', update the reported user's status
    if (action === "block") {
      await User.findByIdAndUpdate(report.reportedUserId, {
        $set: { status: "blocked" },
      });
    }

    res.status(200).json({ message: "Report resolved successfully.", report });
  } catch (error) {
    console.error("Error resolving report:", error);
    res
      .status(500)
      .json({ error: "An error occurred while resolving the report." });
  }
});

app.get("/unread-counts/:userId", getUnreadCounts);

app.get("/api/question", async (req, res) => {
  try {
    // Get today's date at midnight
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Start of the day

    // Check if a question has already been shared today
    let sharedQuestion = await SharedQuestion.findOne({
      date: { $gte: today },
    });

    if (sharedQuestion) {
      // If a question has already been shared today, fetch it
      const question = await Question.findById(sharedQuestion.questionId);
      if (question) {
        return res.json({
          message: "Here is your question for today!",
          question: question.question,
          options: question.options,
        });
      }
    }

    // If no question shared today, delete outdated shared questions
    await SharedQuestion.deleteMany({ date: { $lt: today } });

    // Fetch a random question
    const question = await Question.aggregate([{ $sample: { size: 1 } }]);

    if (!question.length) {
      return res.status(404).json({ message: "No questions available." });
    }

    // Save the new question and set the date to today
    const newSharedQuestion = new SharedQuestion({
      date: today, // Use today's date
      questionId: question[0]._id,
    });
    await newSharedQuestion.save();

    // Respond with the random question
    res.json({
      message: "Here is your question for today!",
      question: question[0].question,
      options: question[0].options,
    });
  } catch (error) {
    console.error("Error fetching question:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.post("/:userId/update-daily-question", async (req, res) => {
  try {
    const { question, answer } = req.body;
    const { userId } = req.params;

    console.log(userId, question, answer);

    if (!question || !answer) {
      console.log("Question and answer are required.");
      return res
        .status(400)
        .json({ message: "Question and answer are required." });
    }

    // Find the user by ID
    const user = await User.findById(userId);

    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: "User not found." });
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0); // Reset to the start of today

    // Check if the user's daily question is from today
    if (user.dailyQuestion?.answeredAt) {
      const answeredDate = new Date(user.dailyQuestion.answeredAt);
      answeredDate.setHours(0, 0, 0, 0); // Reset answeredAt to the start of that day

      // If the question is from today, do not allow a new update
      if (answeredDate.getTime() === today.getTime()) {
        return res
          .status(400)
          .json({ message: "Question has already been answered today." });
      }

      // If the question is from a previous day, delete it
      user.dailyQuestion = null;
    }

    // Update the user's daily question with the new one
    user.dailyQuestion = {
      question,
      answer,
      answeredAt: new Date(),
    };

    await user.save();

    res.status(200).json({ message: "Daily question updated successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

app.use("/notify", userRoutes);

const fetchUsersWithPriorityAndLikes = async () => {
  try {
    const users = await User.aggregate([
      {
        $match: {
          priority: 1,
        },
      },
      {
        $addFields: {
          totalLikesAndDislikes: {
            $add: [{ $size: "$profileDislikes" }, { $size: "$recievedLikes" }],
          },
        },
      },
      {
        $match: {
          totalLikesAndDislikes: { $lt: 15 },
        },
      },
      {
        $project: {
          _id: 1, // Only include the user ID in the result
        },
      },
    ]);

    console.log(users);
    return users;
  } catch (error) {
    console.error("Error fetching users:", error);
  }
};

app.put("/user/:userId/name", async (req, res) => {
  try {
    const { userId } = req.params;
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Name is required." });
    }

    // Update the user's name
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { name },
      { new: true }, // Return the updated document
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({
      message: "Name updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error updating name:", error);
    res.status(500).json({
      message: "An unexpected error occurred while updating the name.",
      error: error.message,
    });
  }
});

app.put("/user/:userId/age", async (req, res) => {
  try {
    const { userId } = req.params;
    const { age } = req.body;

    if (!age || typeof age !== "number") {
      return res.status(400).json({ message: "Valid age is required." });
    }

    // Update the user's age
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { age },
      { new: true }, // Return the updated document
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({
      message: "Age updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error updating age:", error);
    res.status(500).json({
      message: "An unexpected error occurred while updating the age.",
      error: error.message,
    });
  }
});

// Fetch users created between specific dates
app.get("/by-date-range", async (req, res) => {
  try {
    const { startDate, endDate, page = 1, limit = 10 } = req.query;

    console.log(
      `Fetching users between ${startDate} and ${endDate}, page ${page}, limit ${limit}`,
    );

    if (!startDate || !endDate) {
      return res
        .status(400)
        .json({ message: "Both start and end dates are required" });
    }

    // Parse dates and create query range
    const start = new Date(startDate);
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999); // Set to end of day

    // Validate dates
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({ message: "Invalid date format" });
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Query users within date range
    const users = await User.find({
      createdAt: { $gte: start, $lte: end },
    })
      .select("name email age gender profileImages createdAt")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalUsers = await User.countDocuments({
      createdAt: { $gte: start, $lte: end },
    });

    console.log(`Found ${totalUsers} users within date range`);

    return res.status(200).json({
      users,
      totalUsers,
      totalPages: Math.ceil(totalUsers / parseInt(limit)),
      currentPage: parseInt(page),
    });
  } catch (error) {
    console.error("Error fetching users by date range:", error);
    res.status(500).json({
      message: "An error occurred while fetching users",
      error: error.message,
    });
  }
});

// Endpoint for sending customizable push notifications from CMS
app.post("/admin/send-notification", async (req, res) => {
  try {
    const { title, body, userIds, ignoreWeeklyLimit } = req.body;

    if (!title || !body || !userIds || !Array.isArray(userIds)) {
      console.error("[Notification Endpoint] Invalid request parameters:", {
        title,
        body,
        userIds,
      });
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Build query to find users with push tokens
    const query = {
      _id: { $in: userIds.map((id) => new ObjectId(id)) },
      pushToken: { $exists: true, $ne: null },
    };

    // Add weekly limit check if not ignored
    if (!ignoreWeeklyLimit) {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      query.lastNotificationSent = { $lt: oneWeekAgo };
    }

    const users = await User.find(query);

    let successCount = 0;
    let failureCount = 0;
    const errors = [];

    for (const user of users) {
      try {
        await sendNotification(user.pushToken, title, body, {
          type: "admin_broadcast",
        });

        // Update last notification timestamp
        await User.findByIdAndUpdate(user._id, {
          lastNotificationSent: new Date(),
        });

        successCount++;
      } catch (error) {
        failureCount++;
        errors.push({
          userId: user._id,
          error: error.message,
        });
        console.error(
          `[Notification Endpoint] Failed to send notification to user ${user._id}:`,
          error,
        );
      }
    }

    res.json({
      success: true,
      message: `Notifications sent successfully to ${successCount} users${
        failureCount > 0 ? `, ${failureCount} failed` : ""
      }`,
      stats: {
        totalUsers: users.length,
        successCount,
        failureCount,
        errors: errors.length > 0 ? errors : undefined,
      },
    });
  } catch (error) {
    console.error("[Notification Endpoint] Unexpected error:", error);
    res.status(500).json({ error: "Failed to send notifications" });
  }
});

// ─── Regional Campaigns ───────────────────────────────────────────────────────

function localTimeToUTC(localDateStr, tz) {
  if (!localDateStr || !tz || tz === "UTC")
    return localDateStr ? new Date(localDateStr) : null;
  const [datePart, timePart] = localDateStr.split("T");
  if (!datePart || !timePart) return new Date(localDateStr);
  const [year, month, day] = datePart.split("-").map(Number);
  const [hour, minute] = timePart.split(":").map(Number);
  const guess = new Date(Date.UTC(year, month - 1, day, hour, minute));
  const utcStr = guess.toLocaleString("en-US", { timeZone: "UTC" });
  const localStr = guess.toLocaleString("en-US", { timeZone: tz });
  const offsetMs = new Date(localStr).getTime() - new Date(utcStr).getTime();
  return new Date(guess.getTime() - offsetMs);
}

app.get("/admin/regional-campaigns/preview-count", async (req, res) => {
  try {
    const lat = parseFloat(req.query.lat);
    const lng = parseFloat(req.query.lng);
    const radiusM = parseFloat(req.query.radiusM);
    const eventsOnly = req.query.eventsOnly !== "false";
    const gender = req.query.gender || null;

    if (isNaN(lat) || isNaN(lng) || isNaN(radiusM)) {
      return res
        .status(400)
        .json({ error: "lat, lng, and radiusM are required numbers" });
    }

    const matchConditions = [{ pushToken: { $exists: true, $ne: null } }];
    if (eventsOnly) {
      matchConditions.push(
        {
          $or: [
            { lookingFor: { $exists: false } },
            { lookingFor: { $size: 0 } },
          ],
        },
        {
          $or: [
            { availability: { $exists: false } },
            { availability: { $size: 0 } },
          ],
        },
      );
    }
    if (gender) matchConditions.push({ gender });

    const result = await User.aggregate([
      {
        $geoNear: {
          near: { type: "Point", coordinates: [lng, lat] },
          distanceField: "distance",
          maxDistance: radiusM,
          spherical: true,
          query: { $and: matchConditions },
        },
      },
      { $count: "count" },
    ]);

    res.json({ count: result[0]?.count || 0 });
  } catch (err) {
    console.error(
      "[Regional Campaigns] Preview count error:",
      err?.message || err,
    );
    res.status(500).json({ error: "Failed to get preview count" });
  }
});

app.get("/admin/regional-campaigns", async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const statusFilter = req.query.status;
    const query =
      statusFilter && statusFilter !== "all" ? { status: statusFilter } : {};

    const [campaigns, total] = await Promise.all([
      RegionalCampaign.find(query)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      RegionalCampaign.countDocuments(query),
    ]);

    res.json({ campaigns, total, page, limit });
  } catch (err) {
    console.error("[Regional Campaigns] List error:", err?.message || err);
    res.status(500).json({ error: "Failed to list campaigns" });
  }
});

app.post("/admin/regional-campaigns", async (req, res) => {
  try {
    const {
      name,
      regionType,
      country,
      center,
      radiusM,
      title,
      message,
      timezone,
      scheduleAt,
      requirePushToken,
      eventsOnly,
      audience,
      testUser,
    } = req.body;

    if (!name || !regionType || !title || !message) {
      return res
        .status(400)
        .json({ error: "name, regionType, title, and message are required" });
    }

    if (testUser) {
      const lookup = testUser.trim();
      let foundUser;
      if (mongoose.Types.ObjectId.isValid(lookup)) {
        foundUser = await User.findById(lookup)
          .select("_id email name pushToken")
          .lean();
      } else if (lookup.includes("@")) {
        foundUser = await User.findOne({ email: lookup.toLowerCase() })
          .select("_id email name pushToken")
          .lean();
      } else {
        foundUser = await User.findOne({
          name: { $regex: new RegExp(`^${lookup}$`, "i") },
        })
          .select("_id email name pushToken")
          .lean();
      }
      if (!foundUser) {
        return res
          .status(400)
          .json({ error: `Test user "${lookup}" not found` });
      }
      if (!foundUser.pushToken) {
        return res
          .status(400)
          .json({
            error: `Test user "${foundUser.email || foundUser.name}" has no push token`,
          });
      }
    }

    const tz = timezone || "UTC";
    const campaignData = {
      name,
      regionType,
      country: country || null,
      title,
      message,
      timezone: tz,
      scheduleAt: scheduleAt ? localTimeToUTC(scheduleAt, tz) : null,
      requirePushToken: requirePushToken !== false,
      eventsOnly: eventsOnly !== false,
      audience: audience || {},
      testUser: testUser || null,
      status: "draft",
    };

    if (center && center.lat != null && center.lng != null) {
      campaignData.center = {
        type: "Point",
        coordinates: [center.lng, center.lat],
      };
    }
    if (radiusM) campaignData.radiusM = radiusM;

    const campaign = await RegionalCampaign.create(campaignData);
    res.status(201).json(campaign);
  } catch (err) {
    console.error("[Regional Campaigns] Create error:", err?.message || err);
    res.status(500).json({ error: "Failed to create campaign" });
  }
});

app.get("/admin/regional-campaigns/:id", async (req, res) => {
  try {
    const campaign = await RegionalCampaign.findById(req.params.id).lean();
    if (!campaign) return res.status(404).json({ error: "Campaign not found" });
    res.json(campaign);
  } catch (err) {
    console.error("[Regional Campaigns] Get error:", err?.message || err);
    res.status(500).json({ error: "Failed to get campaign" });
  }
});

app.put("/admin/regional-campaigns/:id", async (req, res) => {
  try {
    const campaign = await RegionalCampaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ error: "Campaign not found" });
    if (campaign.status !== "draft") {
      return res
        .status(400)
        .json({ error: "Only draft campaigns can be edited" });
    }

    const {
      name,
      regionType,
      country,
      center,
      radiusM,
      title,
      message,
      timezone,
      scheduleAt,
      requirePushToken,
      eventsOnly,
      audience,
      testUser,
    } = req.body;

    const updates = {};
    if (name != null) updates.name = name;
    if (regionType != null) updates.regionType = regionType;
    if (country !== undefined) updates.country = country || null;
    if (title != null) updates.title = title;
    if (message != null) updates.message = message;
    if (timezone != null) updates.timezone = timezone;
    const updateTz = timezone || campaign.timezone || "UTC";
    if (scheduleAt !== undefined)
      updates.scheduleAt = scheduleAt
        ? localTimeToUTC(scheduleAt, updateTz)
        : null;
    if (requirePushToken != null) updates.requirePushToken = requirePushToken;
    if (eventsOnly != null) updates.eventsOnly = eventsOnly;
    if (audience != null) updates.audience = audience;
    if (testUser !== undefined) {
      if (testUser) {
        const lookup = testUser.trim();
        let foundUser;
        if (mongoose.Types.ObjectId.isValid(lookup)) {
          foundUser = await User.findById(lookup)
            .select("_id email name pushToken")
            .lean();
        } else if (lookup.includes("@")) {
          foundUser = await User.findOne({ email: lookup.toLowerCase() })
            .select("_id email name pushToken")
            .lean();
        } else {
          foundUser = await User.findOne({
            name: { $regex: new RegExp(`^${lookup}$`, "i") },
          })
            .select("_id email name pushToken")
            .lean();
        }
        if (!foundUser) {
          return res
            .status(400)
            .json({ error: `Test user "${lookup}" not found` });
        }
        if (!foundUser.pushToken) {
          return res
            .status(400)
            .json({
              error: `Test user "${foundUser.email || foundUser.name}" has no push token`,
            });
        }
      }
      updates.testUser = testUser || null;
    }
    if (radiusM != null) updates.radiusM = radiusM;
    if (center && center.lat != null && center.lng != null) {
      updates.center = { type: "Point", coordinates: [center.lng, center.lat] };
    }

    const updated = await RegionalCampaign.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true },
    ).lean();
    res.json(updated);
  } catch (err) {
    console.error("[Regional Campaigns] Update error:", err?.message || err);
    res.status(500).json({ error: "Failed to update campaign" });
  }
});

app.delete("/admin/regional-campaigns/:id", async (req, res) => {
  try {
    const result = await RegionalCampaign.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ error: "Campaign not found" });
    res.json({ success: true });
  } catch (err) {
    console.error("[Regional Campaigns] Delete error:", err?.message || err);
    res.status(500).json({ error: "Failed to delete campaign" });
  }
});

app.post("/admin/regional-campaigns/:id/schedule", async (req, res) => {
  try {
    const campaign = await RegionalCampaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ error: "Campaign not found" });
    if (campaign.status !== "draft") {
      return res
        .status(400)
        .json({ error: "Only draft campaigns can be scheduled" });
    }

    const scheduleTz = campaign.timezone || "UTC";
    const scheduleAt = req.body.scheduleAt
      ? localTimeToUTC(req.body.scheduleAt, scheduleTz)
      : campaign.scheduleAt;
    if (!scheduleAt) {
      return res
        .status(400)
        .json({
          error: "scheduleAt is required (set on campaign or in request)",
        });
    }

    const updated = await RegionalCampaign.findByIdAndUpdate(
      req.params.id,
      { status: "scheduled", scheduleAt },
      { new: true },
    ).lean();

    console.log(
      `[Regional Campaigns] Campaign "${campaign.name}" scheduled for ${scheduleAt}`,
    );
    res.json(updated);
  } catch (err) {
    console.error("[Regional Campaigns] Schedule error:", err?.message || err);
    res.status(500).json({ error: "Failed to schedule campaign" });
  }
});

app.post("/admin/regional-campaigns/:id/cancel", async (req, res) => {
  try {
    const campaign = await RegionalCampaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ error: "Campaign not found" });
    if (campaign.status !== "scheduled") {
      return res
        .status(400)
        .json({ error: "Only scheduled campaigns can be cancelled" });
    }

    const updated = await RegionalCampaign.findByIdAndUpdate(
      req.params.id,
      { status: "cancelled" },
      { new: true },
    ).lean();

    console.log(`[Regional Campaigns] Campaign "${campaign.name}" cancelled`);
    res.json(updated);
  } catch (err) {
    console.error("[Regional Campaigns] Cancel error:", err?.message || err);
    res.status(500).json({ error: "Failed to cancel campaign" });
  }
});

app.post("/admin/regional-campaigns/:id/test", async (req, res) => {
  try {
    const campaign = await RegionalCampaign.findById(req.params.id);
    if (!campaign) return res.status(404).json({ error: "Campaign not found" });

    const { userId, userEmail, userName } = req.body;
    if (!userId && !userEmail && !userName) {
      return res
        .status(400)
        .json({ error: "Provide userId, userEmail, or userName" });
    }

    let user;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      user = await User.findById(userId);
    } else if (userEmail) {
      user = await User.findOne({ email: userEmail.toLowerCase().trim() });
    } else if (userName) {
      user = await User.findOne({
        name: { $regex: new RegExp(`^${userName.trim()}$`, "i") },
      });
    }

    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.pushToken) {
      return res.status(400).json({ error: "User does not have a push token" });
    }

    await sendNotification(user.pushToken, campaign.title, campaign.message);

    await Notification.create({
      userId: user._id,
      type: "regional_campaign",
      category: "discovery",
      title: campaign.title,
      message: campaign.message,
    });

    console.log(
      `[Regional Campaigns] Test notification sent to ${user.email || user.name} for campaign "${campaign.name}"`,
    );
    res.json({
      success: true,
      recipient: { _id: user._id, email: user.email, name: user.name },
    });
  } catch (err) {
    console.error("[Regional Campaigns] Test send error:", err?.message || err);
    res.status(500).json({ error: "Failed to send test notification" });
  }
});

app.post("/admin/regional-campaigns/quick-test", async (req, res) => {
  try {
    const { title, message, userId, userEmail, userName } = req.body;
    if (!title || !message) {
      return res.status(400).json({ error: "title and message are required" });
    }
    if (!userId && !userEmail && !userName) {
      return res
        .status(400)
        .json({ error: "Provide userId, userEmail, or userName" });
    }

    let user;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      user = await User.findById(userId);
    } else if (userEmail) {
      user = await User.findOne({ email: userEmail.toLowerCase().trim() });
    } else if (userName) {
      user = await User.findOne({
        name: { $regex: new RegExp(`^${userName.trim()}$`, "i") },
      });
    }

    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.pushToken) {
      return res.status(400).json({ error: "User does not have a push token" });
    }

    await sendNotification(user.pushToken, title, message);
    console.log(
      `[Regional Campaigns] Quick test sent to ${user.email || user.name}: "${title}"`,
    );
    res.json({
      success: true,
      recipient: { _id: user._id, email: user.email, name: user.name },
    });
  } catch (err) {
    console.error(
      "[Regional Campaigns] Quick test error:",
      err?.message || err,
    );
    res.status(500).json({ error: "Failed to send test notification" });
  }
});

// ─── End Regional Campaigns ───────────────────────────────────────────────────

// CMS test endpoint: upload profile image to R2 for the logged-in user
app.post(
  "/admin/me/profile-image",
  requireAuth,
  imageUploadSingle,
  async (req, res) => {
    const userId = req.authUserId;

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    try {
      const normalized = await normalizeProfileImageToJpeg(
        req.file.buffer,
        req.file.mimetype,
      );

      const key = buildUserImageKey({
        userId,
        mimetype: "image/webp",
        originalname: req.file.originalname,
        extOverride: normalized.extension,
      });

      const { url: imageUrl } = await uploadImageBufferToR2({
        buffer: normalized.buffer,
        contentType: normalized.contentType,
        key,
      });

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $addToSet: { profileImages: imageUrl } },
        { new: true },
      ).select("_id name email profileImages");

      if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
      }

      return res.status(200).json({
        message: "Upload was a success",
        imageUrl,
        profileImages: updatedUser.profileImages,
      });
    } catch (error) {
      console.error("R2 file upload failed:", error);
      return res.status(500).json({ error: "File upload failed" });
    }
  },
);

// Endpoint to update user's anonymous mode
app.put("/users/:userId/anonymous", async (req, res) => {
  try {
    const { userId } = req.params;
    const { anonymous } = req.body;

    if (typeof anonymous !== "boolean") {
      return res
        .status(400)
        .json({ message: "Anonymous field must be a boolean" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { anonymous },
      { new: true },
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: "Anonymous mode updated successfully",
      anonymous: updatedUser.anonymous,
    });
  } catch (error) {
    console.error("Error updating anonymous mode:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

// Endpoint to add priority to 1 on profiles that are viewed on the CMS
app.put("/set-priority/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { action } = req.body; // Optional: 'set' or 'remove', if not specified, toggle

    console.log("Updating priority for user:", userId);

    // Validate userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      console.log("Invalid user ID format:", userId);
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    // Find the user first to determine current priority
    const user = await User.findById(userId);

    if (!user) {
      console.log("User not found:", userId);
      return res.status(404).json({ message: "User not found" });
    }

    // Determine new priority value
    let newPriority = 1; // Default to setting priority

    if (action === "remove") {
      newPriority = 0;
    } else if (action === "set") {
      newPriority = 1;
    } else {
      // Toggle behavior - if no specific action provided
      newPriority = user.priority === 1 ? 0 : 1;
    }

    // Update the user's priority
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { priority: newPriority },
      { new: true },
    );

    console.log(
      `Priority ${newPriority === 1 ? "set" : "removed"} for user:`,
      updatedUser.name,
    );
    return res.status(200).json({
      message:
        newPriority === 1
          ? "User priority set successfully"
          : "User priority removed successfully",
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        priority: updatedUser.priority,
      },
    });
  } catch (error) {
    console.error("Error updating user priority:", error);
    res.status(500).json({
      message: "Error updating user priority",
      error: error.message,
    });
  }
});

// Endpoint to flag or unflag a user
app.put("/users/:userId/flag", async (req, res) => {
  try {
    const { userId } = req.params;
    const { flagged, reason } = req.body;

    // Validate the userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    // Make sure flagged is a boolean
    if (typeof flagged !== "boolean") {
      return res
        .status(400)
        .json({ message: "Flagged parameter must be a boolean" });
    }

    // Update user's flagged status
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        flagged: flagged,
        flagReason: flagged ? reason || "Flagged by admin" : "",
      },
      { new: true },
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      message: flagged
        ? "User has been flagged successfully"
        : "User has been unflagged successfully",
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        flagged: updatedUser.flagged,
        flagReason: updatedUser.flagReason,
      },
    });
  } catch (error) {
    console.error("Error updating user flag status:", error);
    return res.status(500).json({
      message: "Error updating user flag status",
      error: error.message,
    });
  }
});

// Endpoint to get total count of flagged profiles
app.get("/admin/flagged-profiles/count", async (req, res) => {
  try {
    // Count all users where flagged is true
    const totalFlagged = await User.countDocuments({ flagged: true });

    return res.status(200).json({
      message: "Flagged profiles count retrieved successfully",
      totalFlagged: totalFlagged,
    });
  } catch (error) {
    console.error("Error counting flagged profiles:", error);
    return res.status(500).json({
      message: "Error counting flagged profiles",
      error: error.message,
    });
  }
});

// Endpoint to get all flagged profiles with pagination
app.get("/admin/flagged-profiles", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      sortBy = "createdAt",
      sortOrder = -1,
    } = req.query;

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Prepare sort options
    const sortOptions = {};
    sortOptions[sortBy] = parseInt(sortOrder);

    // Find all flagged users
    const flaggedUsers = await User.find({ flagged: true })
      .select(
        "name email age gender profileImages flagged flagReason createdAt pushToken location.country",
      )
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalFlagged = await User.countDocuments({ flagged: true });

    return res.status(200).json({
      users: flaggedUsers,
      totalUsers: totalFlagged,
      totalPages: Math.ceil(totalFlagged / parseInt(limit)),
      currentPage: parseInt(page),
      message: "Flagged profiles retrieved successfully",
    });
  } catch (error) {
    console.error("Error fetching flagged profiles:", error);
    return res.status(500).json({
      message: "Error fetching flagged profiles",
      error: error.message,
    });
  }
});

// Endpoint to bulk delete multiple users
app.post("/admin/users/bulk-delete", async (req, res) => {
  try {
    const { userIds } = req.body;

    // Validate input
    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        message: "User IDs array is required and must not be empty",
      });
    }

    console.log(`Attempting to delete ${userIds.length} users`);

    // Validate all IDs are valid ObjectIds
    const validIds = userIds.filter((id) =>
      mongoose.Types.ObjectId.isValid(id),
    );

    if (validIds.length !== userIds.length) {
      return res.status(400).json({
        message: "Some user IDs are invalid",
        invalidCount: userIds.length - validIds.length,
      });
    }

    // Convert to ObjectIds
    const objectIds = validIds.map((id) => new mongoose.Types.ObjectId(id));

    // Delete multiple users
    const result = await User.deleteMany({ _id: { $in: objectIds } });

    // Remove deleted users from all event participants so they no longer appear in any activities
    if (result.deletedCount > 0) {
      await Event.updateMany(
        { "participants.userId": { $in: objectIds } },
        { $pull: { participants: { userId: { $in: objectIds } } } },
      );
    }

    console.log(`Successfully deleted ${result.deletedCount} users`);

    return res.status(200).json({
      message: `Successfully deleted ${result.deletedCount} user(s)`,
      deletedCount: result.deletedCount,
      requestedCount: userIds.length,
    });
  } catch (error) {
    console.error("Error bulk deleting users:", error);
    return res.status(500).json({
      message: "Error deleting users",
      error: error.message,
    });
  }
});

// Endpoint to bulk unflag multiple users
app.post("/admin/users/bulk-unflag", async (req, res) => {
  try {
    const { userIds } = req.body;

    // Validate input
    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        message: "User IDs array is required and must not be empty",
      });
    }

    console.log(`Attempting to unflag ${userIds.length} users`);

    // Validate all IDs are valid ObjectIds
    const validIds = userIds.filter((id) =>
      mongoose.Types.ObjectId.isValid(id),
    );

    if (validIds.length !== userIds.length) {
      return res.status(400).json({
        message: "Some user IDs are invalid",
        invalidCount: userIds.length - validIds.length,
      });
    }

    // Convert to ObjectIds
    const objectIds = validIds.map((id) => new mongoose.Types.ObjectId(id));

    // Update multiple users to unflag them
    const result = await User.updateMany(
      { _id: { $in: objectIds } },
      { $set: { flagged: false, flagReason: "" } },
    );

    console.log(`Successfully unflagged ${result.modifiedCount} users`);

    return res.status(200).json({
      message: `Successfully unflagged ${result.modifiedCount} user(s)`,
      unflaggedCount: result.modifiedCount,
      requestedCount: userIds.length,
    });
  } catch (error) {
    console.error("Error bulk unflagging users:", error);
    return res.status(500).json({
      message: "Error unflagging users",
      error: error.message,
    });
  }
});

// Endpoint to get users with location data and their nearby users
app.get("/users-with-nearby", async (req, res) => {
  try {
    const {
      maxDistance = 50,
      limit = 20,
      page = 1,
      minNearbyCount = 0, // Minimum number of nearby users to include in results
    } = req.query;

    // Parse and validate parameters
    const maxDistanceMeters = parseFloat(maxDistance) * 1000; // Convert km to meters
    const userLimit = parseInt(limit, 10);
    const currentPage = parseInt(page, 10);
    const minNearby = parseInt(minNearbyCount, 10);
    const skip = (currentPage - 1) * userLimit;

    // Build the query for users with valid location data
    const query = {
      "location.coordinates": { $exists: true },
      "location.coordinates.0": { $ne: null, $exists: true },
      "location.coordinates.1": { $ne: null, $exists: true },
      pushToken: { $exists: true, $ne: null },
    };

    // Count total users matching the query for pagination info
    const totalUsers = await User.countDocuments(query);

    // Find users with valid location data with pagination
    const usersWithLocation = await User.find(query)
      .select("_id name email gender location profileImages pushToken")
      .skip(skip)
      .limit(userLimit)
      .lean();

    if (usersWithLocation.length === 0) {
      return res.status(404).json({
        message: "No users with location data found",
        pagination: {
          total: totalUsers,
          page: currentPage,
          limit: userLimit,
          pages: Math.ceil(totalUsers / userLimit),
        },
      });
    }

    // 2. For each user, find nearby users
    const usersWithNearbyData = await Promise.all(
      usersWithLocation.map(async (user) => {
        // Skip users with missing location data
        if (!user.location || !user.location.coordinates) {
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }

        const coordinates = user.location.coordinates;

        // Skip users with invalid coordinates
        if (!Array.isArray(coordinates) || coordinates.length !== 2) {
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }

        const [longitude, latitude] = coordinates;

        // Skip users with invalid coordinates values
        if (
          longitude === undefined ||
          latitude === undefined ||
          longitude === null ||
          latitude === null ||
          isNaN(longitude) ||
          isNaN(latitude) ||
          longitude === 0 ||
          latitude === 0
        ) {
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }

        try {
          // Build the gender query based on the current user's gender
          let genderQuery = {};

          // If the user's gender is male or female, look for opposite gender
          if (user.gender === "male") {
            genderQuery = { gender: "female" };
          } else if (user.gender === "female") {
            genderQuery = { gender: "male" };
          }
          // If the user's gender is not male or female (or undefined),
          // don't filter by gender to show all nearby users

          // Find nearby users
          const nearbyUsers = await User.aggregate([
            {
              $geoNear: {
                near: {
                  type: "Point",
                  coordinates: [longitude, latitude],
                },
                distanceField: "distance",
                maxDistance: maxDistanceMeters,
                spherical: true,
                query: {
                  _id: { $ne: user._id }, // Exclude the user themselves
                  ...genderQuery, // Apply gender filter if applicable
                  profileImages: { $exists: true, $not: { $size: 0 } },
                  flagged: { $ne: true },
                  pushToken: { $exists: true, $ne: null },
                },
                distanceMultiplier: 0.001, // Convert to kilometers
                key: "location",
              },
            },
            {
              $project: {
                _id: 1,
                name: 1,
                gender: 1,
                distance: 1,
                pushToken: 1,
                profileImages: { $slice: ["$profileImages", 1] }, // Only return first profile image
              },
            },
            { $limit: 20 }, // Limit nearby users per person
          ]);

          return {
            ...user,
            nearbyUsers,
            nearbyCount: nearbyUsers.length,
          };
        } catch (error) {
          console.error(
            `Error finding nearby users for user ${user._id}:`,
            error,
          );
          return { ...user, nearbyUsers: [], nearbyCount: 0 };
        }
      }),
    );

    // 3. Filter and sort users by nearby count
    const filteredUsers = usersWithNearbyData
      .filter((user) => user.nearbyCount >= minNearby)
      .sort((a, b) => b.nearbyCount - a.nearbyCount);

    return res.status(200).json({
      pagination: {
        total: totalUsers,
        page: currentPage,
        limit: userLimit,
        pages: Math.ceil(totalUsers / userLimit),
      },
      totalUsersWithLocation: usersWithLocation.length,
      usersWithNearbyUsers: filteredUsers.length,
      users: filteredUsers,
    });
  } catch (error) {
    console.error("Error finding users with nearby data:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint for sending notifications about nearby users via email
app.post("/admin/send-nearby-email", async (req, res) => {
  try {
    const {
      userIds,
      customMessage,
      emailSubject,
      emailTemplate,
      nearbyUserCounts,
      ignoreWeeklyLimit,
    } = req.body;

    if (!userIds || !userIds.length || !customMessage) {
      return res.status(400).json({
        message: "User IDs array and customMessage are required",
      });
    }

    // Calculate one week ago to check for recent notifications
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    // Find users with email addresses who haven't received a notification in the last week
    let query = {
      _id: { $in: userIds },
      email: { $exists: true, $ne: null },
    };

    // Add weekly notification check unless explicitly ignored
    if (!ignoreWeeklyLimit) {
      query.$or = [
        { lastNotificationSent: { $exists: false } },
        { lastNotificationSent: { $lt: oneWeekAgo } },
      ];
    }

    const users = await User.find(query).select("_id name email");

    // Find filtered out users who recently received notifications
    const recentlyNotifiedCount = userIds.length - users.length;

    if (users.length === 0) {
      return res.status(404).json({
        message:
          recentlyNotifiedCount > 0
            ? `All selected users (${recentlyNotifiedCount}) were already notified within the last week`
            : "No users found with valid email addresses",
      });
    }

    console.log(
      `Starting to send emails to ${users.length} users (${recentlyNotifiedCount} filtered out due to recent notifications)`,
    );

    // Send emails to all found users
    const emailPromises = users.map(async (user) => {
      const messageWithCount = customMessage.replace(
        "{count}",
        nearbyUserCounts && nearbyUserCounts[user._id.toString()]
          ? nearbyUserCounts[user._id.toString()].toString()
          : "0",
      );

      // Default template if none provided
      const defaultTemplate = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #6200ee;">Cuddles</h2>
          <p>Hello ${user.name || "there"},</p>
          <p>${messageWithCount}</p>
          <p>Open the Cuddles app to see who's nearby and make connections!</p>
          <p style="margin-top: 20px;">Warm regards,<br>The Cuddles Team</p>
        </div>
      `;

      // Process the custom template if provided
      let htmlContent = defaultTemplate;
      if (emailTemplate) {
        htmlContent = emailTemplate
          .replace("{name}", user.name || "there")
          .replace("{message}", messageWithCount)
          .replace(
            "{count}",
            nearbyUserCounts && nearbyUserCounts[user._id.toString()]
              ? nearbyUserCounts[user._id.toString()].toString()
              : "0",
          );
      }

      const mailOptions = {
        from: "Charlotte from Cuddles <cuddlesquery@gmail.com>",
        to: user.email,
        subject: emailSubject || "Nearby Users Alert",
        text: messageWithCount,
        html: htmlContent,
      };

      try {
        const result = await sendEmailWithRetry(mailOptions);

        if (result.success) {
          // Update the lastNotificationSent timestamp for this user
          await User.findByIdAndUpdate(user._id, {
            lastNotificationSent: new Date(),
          });
        }

        return {
          userId: user._id,
          email: user.email,
          success: result.success,
          messageId: result.messageId,
          error: result.error,
        };
      } catch (error) {
        console.error(`Error sending email to ${user.email}:`, error);
        return {
          userId: user._id,
          email: user.email,
          success: false,
          error: error.message,
        };
      }
    });

    const emailResults = await Promise.all(emailPromises);

    // Count successes and failures
    const successCount = emailResults.filter((result) => result.success).length;
    const failureCount = emailResults.length - successCount;

    console.log(
      `Email sending complete: ${successCount} succeeded, ${failureCount} failed, ${recentlyNotifiedCount} skipped (recently notified)`,
    );

    res.status(200).json({
      message: `Email notifications sent to ${successCount} users, failed for ${failureCount} users${
        recentlyNotifiedCount > 0
          ? `, ${recentlyNotifiedCount} skipped (recently notified)`
          : ""
      }`,
      results: emailResults,
      successCount,
      failureCount,
      skippedCount: recentlyNotifiedCount,
      emailsSent: successCount > 0,
    });
  } catch (error) {
    console.error("Error sending email notifications:", error);
    res.status(500).json({
      message: "Server error",
      error: error.message,
      emailsSent: false,
    });
  }
});

// Get users with filtering options for admin
app.get("/admin/users", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      hasImages,
      priority,
      flagged,
      email,
      name,
      userId,
      country,
      sortBy = "createdAt",
      sortOrder = -1,
    } = req.query;

    // Build query based on filters
    const query = {};

    // Filter by user ID if provided (exact match)
    if (userId) {
      // Check if it's a valid ObjectId format
      if (mongoose.Types.ObjectId.isValid(userId)) {
        query._id = new mongoose.Types.ObjectId(userId);
      } else {
        // If not a valid ObjectId, return empty result
        return res.status(200).json({
          users: [],
          totalUsers: 0,
          totalPages: 0,
          currentPage: parseInt(page),
        });
      }
    }

    // Filter by whether user has profile images
    if (hasImages === "true") {
      query.$expr = { $gt: [{ $size: "$profileImages" }, 0] };
    } else if (hasImages === "false") {
      query.$expr = { $eq: [{ $size: "$profileImages" }, 0] };
    }

    // Filter by priority
    if (priority !== undefined) {
      query.priority = parseInt(priority);
    }

    // Filter by flagged status
    if (flagged === "true") {
      query.flagged = true;
    } else if (flagged === "false") {
      query.flagged = false;
    }

    // Search by email (partial match)
    if (email) {
      query.email = { $regex: email, $options: "i" };
    }

    // Search by name (partial match)
    if (name) {
      query.name = { $regex: name, $options: "i" };
    }

    // Filter by country
    if (country) {
      query["location.country"] = { $regex: country, $options: "i" };
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Prepare sort options
    const sortOptions = {};
    sortOptions[sortBy] = parseInt(sortOrder);

    // Fetch users with query and pagination
    const users = await User.find(query)
      .select(
        "name email age gender profileImages flagged flagReason priority createdAt pushToken location.country",
      )
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalUsers = await User.countDocuments(query);

    return res.status(200).json({
      users,
      totalUsers,
      totalPages: Math.ceil(totalUsers / parseInt(limit)),
      currentPage: parseInt(page),
    });
  } catch (error) {
    console.error("Error fetching filtered users:", error);
    res.status(500).json({
      message: "An error occurred while fetching users",
      error: error.message,
    });
  }
});

// Endpoint to upload verification selfie
app.post(
  "/verify/:userId/verification-selfie",
  imageUploadSingle,
  async (req, res) => {
    const userId = req.params.userId;

    if (!req.file) {
      return res.status(400).json({ error: "No selfie image uploaded" });
    }

    console.log("userId", userId);

    try {
      let normalized;
      try {
        normalized = await normalizeProfileImageToJpeg(
          req.file.buffer,
          req.file.mimetype,
        );
      } catch (e) {
        return res.status(400).json({ error: e?.message || "Invalid image" });
      }

      const key = buildUserImageKey({
        userId,
        mimetype: normalized.contentType,
        originalname: req.file.originalname,
        extOverride: normalized.extension,
      });

      const { url: selfieUrl } = await uploadImageBufferToR2({
        buffer: normalized.buffer,
        contentType: normalized.contentType,
        key,
      });

      // Update the user's profile with the verification selfie URL

      console.log("selfieUrl", selfieUrl);
      if (selfieUrl) {
        const updateData = {
          "profileVerification.selfieUrl": selfieUrl,
          "profileVerification.status": "pending",
          "profileVerification.submittedAt": new Date(),
        };

        if (req.body.instagramUrl) {
          updateData.instagramUrl = req.body.instagramUrl;
        }

        const user = await User.findByIdAndUpdate(userId, updateData, {
          new: true,
        });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
          message: "Verification selfie uploaded successfully",
          selfieUrl,
          status: "pending",
        });
      }
    } catch (error) {
      console.error("Verification selfie upload failed:", error);
      res.status(500).json({ error: "Verification selfie upload failed" });
    }
  },
);

// Endpoint to check verification status
app.get("/users/:userId/verification-status", async (req, res) => {
  const userId = req.params.userId;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({
      verificationStatus: user.profileVerification?.status || "not_submitted",
      selfieUrl: user.profileVerification?.selfieUrl || null,
      submittedAt: user.profileVerification?.submittedAt || null,
      instagramUrl: user.instagramUrl || "",
    });
  } catch (error) {
    console.error("Error checking verification status:", error);
    res.status(500).json({ error: "Failed to check verification status" });
  }
});

// Admin endpoint to update verification status
app.put("/admin/users/:userId/verification-status", async (req, res) => {
  const { userId } = req.params;
  const { status, adminId, notes } = req.body;

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }

  try {
    // Optional: Add admin authentication check here

    const user = await User.findByIdAndUpdate(
      userId,
      {
        "profileVerification.status": status,
        "profileVerification.reviewedAt": new Date(),
        "profileVerification.reviewedBy": adminId,
        "profileVerification.notes": notes,
      },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // If the user is approved, you might want to add a verified badge to their profile
    if (status === "approved") {
      // This uses the existing verified flag in the schema
      user.verified = true;
      await user.save();
    }

    return res.status(200).json({
      message: `Verification ${status}`,
      user: {
        id: user._id,
        name: user.name,
        profileVerification: user.profileVerification,
      },
    });
  } catch (error) {
    console.error("Error updating verification status:", error);
    res.status(500).json({ error: "Failed to update verification status" });
  }
});

// Endpoint to get all pending verifications
app.get("/admin/verifications/pending", async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Find users with pending verification status
    const pendingVerifications = await User.find({
      "profileVerification.status": "pending",
      "profileVerification.selfieUrl": { $ne: null },
    })
      .select(
        "_id name email profileVerification.selfieUrl profileVerification.submittedAt profileImages",
      )
      .sort({ "profileVerification.submittedAt": -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalCount = await User.countDocuments({
      "profileVerification.status": "pending",
      "profileVerification.selfieUrl": { $ne: null },
    });

    return res.status(200).json({
      verifications: pendingVerifications,
      totalVerifications: totalCount,
      totalPages: Math.ceil(totalCount / parseInt(limit)),
      currentPage: parseInt(page),
    });
  } catch (error) {
    console.error("Error fetching pending verifications:", error);
    res.status(500).json({ error: "Failed to fetch pending verifications" });
  }
});

// Add this function before the message handling code
const sendPushNotification = async (receiverId, title, body, data = {}) => {
  try {
    const user = await User.findById(receiverId);
    if (!user) {
      console.log(`[Push Notification] User not found with ID ${receiverId}`);
      return;
    }

    if (!user.pushToken) {
      console.log(
        `[Push Notification] No push token found for user ${receiverId}`,
      );
      return;
    }

    if (
      !user.pushToken.startsWith("ExponentPushToken[") ||
      !user.pushToken.endsWith("]")
    ) {
      console.log(
        `[Push Notification] Invalid push token format for user ${receiverId}`,
      );
      return;
    }

    console.log(
      `[Push Notification] Sending message notification to user ${receiverId}`,
    );
    await sendNotification(user.pushToken, title, body, data);
    console.log(`[Push Notification] Successfully sent to user ${receiverId}`);
  } catch (error) {
    console.error(
      `[Push Notification] Error sending to user ${receiverId}:`,
      error,
    );
  }
};

// Endpoint to get users with received likes for admin panel
app.get("/admin/users-with-likes", async (req, res) => {
  try {
    const {
      limit = 20,
      page = 1,
      minLikesCount = 0, // Minimum number of likes to include in results
    } = req.query;

    // Parse and validate parameters
    const userLimit = parseInt(limit, 10);
    const currentPage = parseInt(page, 10);
    const minLikes = parseInt(minLikesCount, 10);
    const skip = (currentPage - 1) * userLimit;

    // Build the query for users with received likes AND valid push tokens
    const query = {
      recievedLikes: { $exists: true, $not: { $size: 0 } },
      pushToken: { $exists: true, $ne: null, $ne: "" }, // Ensure pushToken exists, isn't null, and isn't empty
    };

    // Count total users matching the query for pagination info
    const totalUsers = await User.countDocuments(query);

    // Find users with received likes with pagination
    const usersWithLikes = await User.find(query)
      .select("_id name email gender profileImages pushToken recievedLikes")
      .skip(skip)
      .limit(userLimit)
      .lean();

    if (usersWithLikes.length === 0) {
      return res.status(404).json({
        message: "No users with received likes and push tokens found",
        pagination: {
          total: totalUsers,
          page: currentPage,
          limit: userLimit,
          pages: Math.ceil(totalUsers / userLimit),
        },
      });
    }

    // For each user, get detailed information about who liked them
    const usersWithLikesData = await Promise.all(
      usersWithLikes.map(async (user) => {
        try {
          // Get users who liked this person
          const likesDetails = await User.find(
            { _id: { $in: user.recievedLikes } },
            {
              _id: 1,
              name: 1,
              gender: 1,
              profileImages: { $slice: 1 },
              pushToken: 1,
            },
          ).lean();

          return {
            ...user,
            likedBy: likesDetails,
            likesCount: likesDetails.length,
          };
        } catch (error) {
          console.error(
            `Error fetching like details for user ${user._id}:`,
            error,
          );
          return { ...user, likedBy: [], likesCount: 0 };
        }
      }),
    );

    // Filter and sort users by likes count
    const filteredUsers = usersWithLikesData
      .filter((user) => user.likesCount >= minLikes)
      .sort((a, b) => b.likesCount - a.likesCount);

    return res.status(200).json({
      pagination: {
        total: totalUsers,
        page: currentPage,
        limit: userLimit,
        pages: Math.ceil(totalUsers / userLimit),
      },
      totalUsersWithLikes: usersWithLikes.length,
      usersWithFilteredLikes: filteredUsers.length,
      users: filteredUsers,
    });
  } catch (error) {
    console.error("Error finding users with received likes:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint to send push notifications to users with received likes
app.post("/admin/send-likes-notification", async (req, res) => {
  try {
    const {
      userIds,
      customMessage,
      emailSubject,
      emailTemplate,
      likesDetails,
      ignoreWeeklyLimit = false,
    } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        message: "User IDs are required and must be a non-empty array",
        success: false,
      });
    }

    if (!customMessage) {
      return res.status(400).json({
        message: "Custom message is required",
        success: false,
      });
    }

    // Track success and failure counts
    let successCount = 0;
    let failureCount = 0;
    let skippedCount = 0;
    let emailCount = 0;
    let pushCount = 0;

    // Process each user in the array
    await Promise.all(
      userIds.map(async (userId) => {
        try {
          // Get the user with their received likes
          const user = await User.findById(userId)
            .select("name email pushToken recievedLikes lastNotificationSent")
            .lean();

          if (!user) {
            console.log(`User ${userId} not found`);
            failureCount++;
            return;
          }

          // Check if we should skip due to weekly limit
          if (!ignoreWeeklyLimit && user.lastNotificationSent) {
            const lastSentDate = new Date(user.lastNotificationSent);
            const now = new Date();
            const daysSinceLastNotification = Math.floor(
              (now - lastSentDate) / (1000 * 60 * 60 * 24),
            );

            if (daysSinceLastNotification < 7) {
              console.log(
                `Skipping user ${userId} due to weekly notification limit`,
              );
              skippedCount++;
              return;
            }
          }

          // Get the count of likes
          const likesCount = user.recievedLikes ? user.recievedLikes.length : 0;

          if (likesCount === 0) {
            console.log(`User ${userId} has no received likes, skipping`);
            skippedCount++;
            return;
          }

          // Track if any notification was sent
          let notificationSent = false;

          // Send push notification if the user has a push token
          if (user.pushToken) {
            try {
              // Customize the notification message
              const title = "You have new likes!";
              const body = customMessage.replace(
                "{likesCount}",
                likesCount.toString(),
              );

              await sendNotification(user.pushToken, title, body, {
                type: "likes_campaign",
              });
              pushCount++;
              notificationSent = true;
              console.log(`Push notification sent to user ${userId}`);
            } catch (pushError) {
              console.error(
                `Error sending push notification to user ${userId}:`,
                pushError,
              );
            }
          }

          // Send email if emailTemplate is provided and user has an email
          if (emailTemplate && emailSubject && user.email) {
            try {
              // Customize the email content
              const userName = user.name || "there";
              const emailBody = emailTemplate
                .replace(/{name}/g, userName)
                .replace(/{likesCount}/g, likesCount.toString());

              const mailOptions = {
                from: "Charlotte from Cuddles <cuddlesquery@gmail.com>",
                to: user.email,
                subject: emailSubject.replace(
                  /{likesCount}/g,
                  likesCount.toString(),
                ),
                html: emailBody,
              };

              const emailResult = await sendEmailWithRetry(mailOptions);

              if (emailResult.success) {
                emailCount++;
                notificationSent = true;
                console.log(
                  `Email notification sent to user ${userId} at ${user.email}`,
                );
              } else {
                console.error(
                  `Failed to send email to user ${userId}:`,
                  emailResult.error,
                );
              }
            } catch (emailError) {
              console.error(
                `Error sending email to user ${userId}:`,
                emailError,
              );
            }
          }

          // If any notification was sent, update the last notification timestamp
          if (notificationSent) {
            await User.findByIdAndUpdate(userId, {
              lastNotificationSent: new Date(),
            });

            // Increment success count
            successCount++;
          } else {
            failureCount++;
          }
        } catch (error) {
          console.error(`Error sending notification to user ${userId}:`, error);
          failureCount++;
        }
      }),
    );

    // Return the response with counts
    return res.status(200).json({
      message: `Notifications processed: ${successCount} sent, ${failureCount} failed, ${skippedCount} skipped (${pushCount} push, ${emailCount} email)`,
      successCount,
      failureCount,
      skippedCount,
      pushCount,
      emailCount,
      success: successCount > 0,
    });
  } catch (error) {
    console.error("Error sending likes notifications:", error);
    return res.status(500).json({
      message: "Error sending likes notifications",
      error: error.message,
      success: false,
    });
  }
});

// Support email endpoint
app.post("/support-email", async (req, res) => {
  try {
    const { userId, subject, message, userEmail } = req.body;

    if (!userId || !subject || !message || !userEmail) {
      return res.status(400).json({
        message: "Missing required fields: userId, subject, message, userEmail",
      });
    }

    // Get user details
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const mailOptions = {
      from: "Cuddles Support <cuddlesquery@gmail.com>",
      to: "cuddlesquery@gmail.com", // Support team email
      subject: `Support Request: ${subject}`,
      html: `
        <h3>Support Request from Cuddles App</h3>
        <p><strong>User ID:</strong> ${userId}</p>
        <p><strong>User Email:</strong> ${userEmail}</p>
        <p><strong>User Name:</strong> ${user.name || "Not provided"}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, "<br>")}</p>
        <hr>
        <p><em>This email was sent from the Cuddles mobile app support form.</em></p>
      `,
    };

    const result = await sendEmailWithRetry(mailOptions);

    if (result.success) {
      // Send confirmation email to user
      const confirmationMailOptions = {
        from: "Cuddles Support <cuddlesquery@gmail.com>",
        to: userEmail,
        subject: "Support Request Received - Cuddles",
        html: `
          <h3>Thank you for contacting Cuddles Support!</h3>
          <p>We have received your support request and will get back to you as soon as possible.</p>
          <p><strong>Your request details:</strong></p>
          <p><strong>Subject:</strong> ${subject}</p>
          <p><strong>Message:</strong></p>
          <p>${message.replace(/\n/g, "<br>")}</p>
          <hr>
          <p>If you have any urgent concerns, please don't hesitate to reach out to us directly.</p>
          <p>Best regards,<br>The Cuddles Team</p>
        `,
      };

      await sendEmailWithRetry(confirmationMailOptions);

      res.status(200).json({
        message: "Support request sent successfully",
        success: true,
      });
    } else {
      res.status(500).json({
        message: "Failed to send support request",
        error: result.error,
        success: false,
      });
    }
  } catch (error) {
    console.error("Error sending support email:", error);
    res.status(500).json({
      message: "Error sending support request",
      error: error.message,
      success: false,
    });
  }
});

// ============================================================
// OPEN TABLES / EVENTS ENDPOINTS
// ============================================================

// Helper function to update event status based on time
const updateEventStatus = async (event) => {
  const previousStatus = event.status;
  const newStatus = computeNextEventStatus(event);

  if (newStatus !== event.status) {
    await Event.updateOne({ _id: event._id }, { $set: { status: newStatus } });
    event.status = newStatus;
    if (previousStatus !== "ended" && newStatus === "ended") {
      try {
        const payoutUpdate = await markEventPayoutsEligible({
          eventId: event._id.toString(),
        });
        console.log("[EventStatus] Marked host payout ledger rows eligible", {
          eventId: event._id.toString(),
          ...payoutUpdate,
        });
      } catch (error) {
        console.error("[EventStatus] Failed to mark payouts eligible", {
          eventId: event._id.toString(),
          message: error?.message,
        });
      }
    }
  }

  return event;
};

/** Persist status transitions for active events (used by cron; avoids per-read work on /events/nearby). */
const syncEventStatusesBatch = async () => {
  const started = Date.now();
  const cursor = Event.find({
    status: { $in: ["upcoming", "live", "full"] },
  }).cursor();

  const bulkOps = [];
  const transitionedToEnded = [];
  for await (const doc of cursor) {
    const next = computeNextEventStatus(doc);
    if (next !== doc.status) {
      if (doc.status !== "ended" && next === "ended") {
        transitionedToEnded.push(doc._id.toString());
      }
      bulkOps.push({
        updateOne: {
          filter: { _id: doc._id },
          update: { $set: { status: next } },
        },
      });
    }
  }

  if (bulkOps.length > 0) {
    await Event.bulkWrite(bulkOps, { ordered: false });
  }

  for (const eventId of transitionedToEnded) {
    try {
      await markEventPayoutsEligible({ eventId });
    } catch (error) {
      console.error("[EventStatusSync] Failed to mark payouts eligible", {
        eventId,
        message: error?.message,
      });
    }
  }

  console.log(
    `[EventStatusSync] Done in ${Date.now() - started}ms, updated ${bulkOps.length} event(s)`,
  );
};

/** Best-effort remove event cover from R2 when the event document is removed. */
async function deleteEventCoverImageFromR2(coverImageUrl) {
  if (!coverImageUrl) return;
  const key = keyFromPublicUrl(coverImageUrl);
  if (!key) return;
  try {
    await deleteObjectFromR2(key);
  } catch (e) {
    console.warn("[Event R2] Cover image delete failed:", e?.message);
  }
}

const cleanupExpiredEvents = async () => {
  try {
    const cutoffDate = new Date(Date.now() - 6 * 60 * 60 * 1000); // 6 hours ago
    console.log(
      `[Event Cleanup] Starting cleanup at ${new Date().toISOString()}`,
    );
    console.log(
      `[Event Cleanup] Deleting events with startTime before: ${cutoffDate.toISOString()}`,
    );

    const eventsToDelete = await Event.find({
      startTime: { $lte: cutoffDate },
    }).select("_id participants missionStatsCounted coverImage");
    for (const event of eventsToDelete) {
      if (event.missionStatsCounted) {
        continue;
      }

      const toCredit = (event.participants || []).filter(
        (p) =>
          p && (p.status === "going" || p.status === "checked_in") && p.userId,
      );
      for (const p of toCredit) {
        const uid = p.userId._id || p.userId;
        if (uid) {
          try {
            await User.findByIdAndUpdate(uid, { $inc: { eventsAttended: 1 } });
          } catch (err) {
            console.error(
              "[Event Cleanup] Error incrementing eventsAttended for user:",
              uid,
              err,
            );
          }
        }
      }

      await incrementMissionStats({
        strangersConnectedDelta: toCredit.length,
      });

      // Safety-net: backfill coAttendees for all checked-in pairs before deletion
      const checkedIn = (event.participants || []).filter(
        (p) => p && p.status === "checked_in" && p.userId,
      );
      for (let i = 0; i < checkedIn.length; i++) {
        for (let j = i + 1; j < checkedIn.length; j++) {
          const idA = checkedIn[i].userId._id || checkedIn[i].userId;
          const idB = checkedIn[j].userId._id || checkedIn[j].userId;
          try {
            await User.findByIdAndUpdate(idA, {
              $addToSet: { coAttendees: idB },
            });
            await User.findByIdAndUpdate(idB, {
              $addToSet: { coAttendees: idA },
            });
          } catch (coErr) {
            console.error(
              "[Event Cleanup] Error backfilling coAttendees:",
              coErr,
            );
          }
        }
      }

      await Event.findByIdAndUpdate(event._id, {
        $set: { missionStatsCounted: true },
      });
    }

    const result = await Event.deleteMany({
      startTime: { $lte: cutoffDate },
    });

    for (const ev of eventsToDelete) {
      await deleteEventCoverImageFromR2(ev.coverImage);
    }

    console.log(
      `[Event Cleanup] Cleanup completed. Removed ${result.deletedCount} event(s)`,
    );

    return result;
  } catch (error) {
    console.error("[Event Cleanup] Error deleting old events:", error);
    throw error;
  }
};

// Schedule cleanup to run every hour
cron.schedule("0 * * * *", () => {
  console.log(
    `[Event Cleanup] Cron job triggered at ${new Date().toISOString()}`,
  );
  cleanupExpiredEvents().catch((error) => {
    console.error("[Event Cleanup] Cron job error:", error);
  });
});

// Keep event status in sync with time/capacity (so reads like /events/nearby stay fast)
cron.schedule("*/5 * * * *", () => {
  syncEventStatusesBatch().catch((error) => {
    console.error("[EventStatusSync] Cron error:", error);
  });
});

// Run cleanup on startup
console.log(`[Event Cleanup] Running initial cleanup on server startup`);
cleanupExpiredEvents().catch((error) => {
  console.error("[Event Cleanup] Initial cleanup error:", error);
});

// Expire pending suggestions that have passed their expiresAt time
const expireSuggestions = async () => {
  try {
    const now = new Date();
    console.log(
      `[Suggestion Expiry] Starting expiry check at ${now.toISOString()}`,
    );

    // Find suggestions that have expired
    const expiredSuggestions = await Event.find({
      status: "suggested",
      expiresAt: { $lte: now },
    }).populate("hostId", "name pushToken");

    if (expiredSuggestions.length === 0) {
      return;
    }

    console.log(
      `[Suggestion Expiry] Found ${expiredSuggestions.length} expired suggestions`,
    );

    for (const suggestion of expiredSuggestions) {
      try {
        // Mark as cancelled
        await Event.findByIdAndUpdate(suggestion._id, { status: "cancelled" });

        // Notify the suggester that their suggestion expired
        if (suggestion.hostId) {
          await createNotificationWithCaps({
            userId: suggestion.hostId._id,
            type: "suggestion_expired",
            title: "Suggestion Expired",
            message: `Your activity suggestion "${suggestion.title}" has expired without a response`,
            eventId: suggestion._id,
            eventName: suggestion.title,
          });
        }

        console.log(
          `[Suggestion Expiry] Expired suggestion: ${suggestion.title}`,
        );
      } catch (notifError) {
        console.error(
          `[Suggestion Expiry] Error processing suggestion ${suggestion._id}:`,
          notifError,
        );
      }
    }

    console.log(
      `[Suggestion Expiry] Processed ${expiredSuggestions.length} expired suggestions`,
    );
  } catch (error) {
    console.error("[Suggestion Expiry] Error expiring suggestions:", error);
    throw error;
  }
};

// Schedule suggestion expiry to run every 15 minutes
cron.schedule("*/15 * * * *", () => {
  console.log(
    `[Suggestion Expiry] Cron job triggered at ${new Date().toISOString()}`,
  );
  expireSuggestions().catch((error) => {
    console.error("[Suggestion Expiry] Cron job error:", error);
  });
});

// Run suggestion expiry on startup
console.log(
  `[Suggestion Expiry] Running initial expiry check on server startup`,
);
expireSuggestions().catch((error) => {
  console.error("[Suggestion Expiry] Initial expiry error:", error);
});

// Send reminder notifications for events starting within 1 hour
const sendEventReminders = async () => {
  try {
    const now = new Date();
    const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);

    // Find upcoming events starting within 1 hour that haven't had reminders sent
    const upcomingEvents = await Event.find({
      startTime: { $gte: now, $lte: oneHourFromNow },
      status: "upcoming",
      reminderSent: { $ne: true },
    }).populate("participants.userId", "name preferredLanguage");

    if (upcomingEvents.length === 0) {
      return;
    }

    console.log(
      `[Event Reminder] Found ${upcomingEvents.length} events starting soon`,
    );

    for (const event of upcomingEvents) {
      // Calculate time until event starts
      const minutesUntilStart = Math.round(
        (event.startTime - now) / (1000 * 60),
      );
      const timeString =
        minutesUntilStart > 60
          ? "1 hour"
          : minutesUntilStart > 1
            ? `${minutesUntilStart} minutes`
            : "soon";

      const eventReminderStr = getStrings("en").eventReminder;
      // Send reminder to all participants
      for (const participant of event.participants) {
        try {
          const lang = participant.userId?.preferredLanguage;
          const str =
            lang && getStrings(lang).eventReminder
              ? getStrings(lang).eventReminder
              : eventReminderStr;
          const title = str.title;
          const message = interpolate(str.body, {
            eventTitle: event.title,
            timeString,
          });
          await createNotificationWithCaps({
            userId: participant.userId._id || participant.userId,
            type: "event_reminder",
            title,
            message,
            eventId: event._id,
            eventName: event.title,
          });
        } catch (notifError) {
          console.error(
            `Error creating reminder notification for user ${participant.userId}:`,
            notifError,
          );
        }
      }

      // Mark event as reminder sent
      event.reminderSent = true;
      await event.save();

      console.log(
        `[Event Reminder] Sent reminders for event "${event.title}" to ${event.participants.length} participants`,
      );
    }
  } catch (error) {
    console.error("[Event Reminder] Error sending reminders:", error);
  }
};

// Schedule event reminders to run every 15 minutes
cron.schedule("*/15 * * * *", sendEventReminders);
// Run once on startup
sendEventReminders().catch((error) =>
  console.error("[Event Reminder] Error on startup:", error),
);

// Send rating reminders: 2 hours after table ends (plan); if no endTime, fallback to 4h after startTime
const sendRatingReminders = async () => {
  try {
    const now = new Date();
    const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
    const fourHoursAgo = new Date(now.getTime() - 4 * 60 * 60 * 1000);

    const endedEvents = await Event.find({
      status: "ended",
      ratingReminderSent: { $ne: true },
    })
      .populate("participants.userId", "name pushToken preferredLanguage")
      .populate("hostId", "name");

    const readyForReminder = endedEvents.filter((e) => {
      if (e.endTime && e.endTime.getTime() <= twoHoursAgo.getTime())
        return true;
      if (
        !e.endTime &&
        e.startTime &&
        e.startTime.getTime() <= fourHoursAgo.getTime()
      )
        return true;
      return false;
    });

    if (readyForReminder.length === 0) return;

    console.log(
      `[Rating Reminder] Found ${readyForReminder.length} events needing rating reminders`,
    );

    for (const event of readyForReminder) {
      const hostId = (event.hostId._id || event.hostId).toString();

      for (const participant of event.participants) {
        const pUserId = participant.userId?._id || participant.userId;
        if (!pUserId) continue;
        if (pUserId.toString() === hostId) continue;
        if (
          participant.status !== "going" &&
          participant.status !== "checked_in"
        )
          continue;

        try {
          const hostName = event.hostId?.name || "your host";
          const lang = participant.userId?.preferredLanguage;
          const str =
            lang && getStrings(lang).rateHost
              ? getStrings(lang).rateHost
              : getStrings("en").rateHost;
          const title = str.title;
          const message = interpolate(str.body, { hostName });
          await createNotificationWithCaps({
            userId: pUserId,
            type: "rate_host",
            title,
            message,
            eventId: event._id,
            eventName: event.title,
          });
        } catch (notifError) {
          console.error(
            `[Rating Reminder] Error notifying user ${pUserId}:`,
            notifError,
          );
        }
      }

      event.ratingReminderSent = true;
      await event.save();
      console.log(`[Rating Reminder] Sent reminders for "${event.title}"`);
    }
  } catch (error) {
    console.error("[Rating Reminder] Error:", error);
  }
};

cron.schedule("*/30 * * * *", sendRatingReminders);
sendRatingReminders().catch((error) =>
  console.error("[Rating Reminder] Error on startup:", error),
);

// Cape Town weekend nudge: users within 80km of Cape Town, re-engagement cap, batch send
const CAPETOWN_LNG = 18.4241;
const CAPETOWN_LAT = -33.9249;
const CAPETOWN_RADIUS_M = 80000;

const sendCapetownWeekendNudge = async () => {
  const now = new Date();
  if (now.getDay() !== 6) return; // Saturday only
  if (process.env.REDIS_URL && getQueue()) {
    enqueueCapetownWeekend();
    console.log("[Capetown Weekend] Enqueued capetown_weekend job");
    return;
  }
  try {
    const capetownStr = getStrings("en").capetownWeekend;
    if (!capetownStr) return;
    const title = capetownStr.title;
    const body = capetownStr.body;
    const users = await User.aggregate([
      {
        $geoNear: {
          near: { type: "Point", coordinates: [CAPETOWN_LNG, CAPETOWN_LAT] },
          distanceField: "distance",
          maxDistance: CAPETOWN_RADIUS_M,
          spherical: true,
          query: {
            $and: [
              { pushToken: { $exists: true, $ne: null } },
              ...EVENTS_ONLY_QUERY.$and,
            ],
          },
        },
      },
      { $limit: 500 },
      { $project: { _id: 1, pushToken: 1, preferredLanguage: 1 } },
    ]);
    const messages = [];
    for (const u of users) {
      const { allowed } = await shouldSendNotification(u._id, "re_engagement");
      if (!allowed) continue;
      await createNotificationWithCaps({
        userId: u._id,
        type: "capetown_weekend",
        title,
        message: body,
        skipPush: true,
      });
      if (u.pushToken) messages.push({ to: u.pushToken, title, body });
    }
    if (messages.length > 0) {
      await sendNotificationBatch(messages);
      console.log(`[Capetown Weekend] Sent ${messages.length} notifications`);
    }
  } catch (err) {
    console.error("[Capetown Weekend] Error:", err?.message || err);
  }
};

cron.schedule("0 12 * * *", sendCapetownWeekendNudge);

// ─── Regional Campaign scheduler — runs every minute ─────────────────────────
cron.schedule("* * * * *", async () => {
  try {
    const now = new Date();
    const due = await RegionalCampaign.find({
      status: "scheduled",
      scheduleAt: { $lte: now },
    });
    for (const campaign of due) {
      console.log(
        `[Campaign Cron] Dispatching campaign "${campaign.name}" (${campaign._id})`,
      );
      try {
        if (getQueue()) {
          enqueueCampaign(campaign._id);
          console.log(
            `[Campaign Cron] Enqueued "${campaign.name}" to Bull queue`,
          );
        } else {
          await executeCampaign(campaign._id, {
            shouldSendNotification,
            createNotificationWithCaps,
          });
        }
      } catch (err) {
        console.error(
          `[Campaign Cron] Failed to dispatch "${campaign.name}":`,
          err?.message || err,
        );
      }
    }
  } catch (err) {
    console.error("[Campaign Cron] Error:", err?.message || err);
  }
});

// ─── Priority Boost cron — runs every 5 minutes ──────────────────────────────
cron.schedule("*/5 * * * *", async () => {
  try {
    const now = new Date();
    const warningThreshold = new Date(now.getTime() - 18 * 60 * 60 * 1000);

    // T+18h: send 6-hour warning to boosts that have been active for 18h
    const needWarning = await Boost.find({
      status: "active",
      activatedAt: { $lte: warningThreshold },
      warningNotifSent: false,
    }).populate("userId", "pushToken preferredLanguage");

    for (const boost of needWarning) {
      if (boost.userId?.pushToken) {
        try {
          const warnStr = getStrings(
            boost.userId.preferredLanguage,
          ).boostWarning;
          await sendNotification(
            boost.userId.pushToken,
            warnStr.title,
            warnStr.body,
            {
              type: "boost_warning",
            },
          );
        } catch (e) {
          console.error("[Boost Cron] Warning notif failed:", e?.message);
        }
      }
      boost.warningNotifSent = true;
      await boost.save();
    }

    // T+24h: expire boosts and send expiry notification
    const expired = await Boost.find({
      status: "active",
      expiresAt: { $lte: now },
      expiryNotifSent: false,
    }).populate(
      "userId",
      "pushToken preferredLanguage boostCredits coordinates",
    );

    for (const boost of expired) {
      // Coverage % calculation: impressionCount / distinct active users in same radius
      let coverage = 0;
      try {
        const userDoc = await User.findById(boost.userId._id)
          .select("coordinates")
          .lean();
        const coords = userDoc?.coordinates?.coordinates;
        let activeUsersInRadius = 1;
        if (coords && coords.length === 2) {
          activeUsersInRadius = await User.countDocuments({
            _id: { $ne: boost.userId._id },
            coordinates: {
              $geoWithin: {
                $centerSphere: [coords, 50 / 6378.1],
              },
            },
            updatedAt: {
              $gte: new Date(boost.activatedAt.getTime() - 24 * 60 * 60 * 1000),
            },
          });
        }
        coverage = Math.min(
          95,
          Math.round(
            (boost.impressionCount / Math.max(1, activeUsersInRadius)) * 100,
          ),
        );
      } catch (e) {
        console.error("[Boost Cron] Coverage calc failed:", e?.message);
      }

      const creditsLeft = boost.userId?.boostCredits?.remaining ?? 0;

      boost.status = "expired";
      boost.expiryNotifSent = true;
      await boost.save();

      // Reset priority
      await User.findByIdAndUpdate(boost.userId._id, { priority: 0 });

      const expiredStr = getStrings(
        boost.userId?.preferredLanguage,
      ).boostExpired;
      const expiredTitle = expiredStr.title;
      const expiredBody = interpolate(expiredStr.body, {
        coverage,
        count: creditsLeft,
        s: creditsLeft !== 1 ? "s" : "",
      });

      if (boost.userId?.pushToken) {
        try {
          await sendNotification(
            boost.userId.pushToken,
            expiredTitle,
            expiredBody,
            {
              type: "boost_expired",
            },
          );
        } catch (e) {
          console.error("[Boost Cron] Expiry notif failed:", e?.message);
        }
      }

      try {
        await createNotificationWithCaps({
          userId: boost.userId._id,
          type: "boost_expired",
          title: expiredTitle,
          message: expiredBody,
        });
      } catch (e) {
        console.error("[Boost Cron] Expiry in-app notif failed:", e?.message);
      }

      console.log(
        `[Boost Cron] Expired boost ${boost._id} for user ${boost.userId._id}, coverage ${coverage}%`,
      );
    }
  } catch (error) {
    console.error("[Boost Cron] Error:", error);
  }
});
// ─────────────────────────────────────────────────────────────────────────────

// Create new event
app.get("/events/capacity-limits", (req, res) => {
  res.status(200).json(getCapacityLimits());
});

app.post("/events", async (req, res) => {
  try {
    const {
      hostId,
      title,
      description,
      location,
      coverImage,
      link,
      startTime,
      endTime,
      capacity,
      tags,
      status,
      suggestedToUserId,
      suggestedToUserIds, // Array for group invites
      expiresAt,
      audience,
      requiresApproval,
      isPaid,
      priceAmount,
      currency,
      paymentPolicy,
      websiteVisible,
    } = req.body;

    const normalizedLink =
      link != null && String(link).trim()
        ? String(link).trim()
        : null;
    if (normalizedLink && !/^https?:\/\//i.test(normalizedLink)) {
      return res.status(400).json({
        message: "link must be a valid http(s) URL",
      });
    }

    // Validate required fields
    if (!hostId || !title || !location || !startTime) {
      return res.status(400).json({
        message: "Missing required fields: hostId, title, location, startTime",
      });
    }

    // Validate location structure
    if (!location.coordinates || !location.name) {
      return res.status(400).json({
        message: "Location must include coordinates and name",
      });
    }

    // Validate startTime is in the future
    if (new Date(startTime) <= new Date()) {
      return res.status(400).json({
        message: "Start time must be in the future",
      });
    }

    // Check if host exists
    const host = await User.findById(hostId);
    if (!host) {
      return res.status(404).json({ message: "Host user not found" });
    }

    if (!host.profileImages || host.profileImages.length === 0) {
      return res.status(400).json({
        message: "profile_incomplete",
        detail: "You need a profile photo before creating an activity",
      });
    }

    // Validate host gender matches audience restriction
    if (audience === "women_only" && host.gender !== "female") {
      return res
        .status(400)
        .json({ message: "Only women can create women-only events" });
    }
    if (audience === "men_only" && host.gender !== "male") {
      return res
        .status(400)
        .json({ message: "Only men can create men-only events" });
    }

    const normalizedIsPaid = Boolean(isPaid);
    const normalizedPriceAmount = Number(priceAmount || 0);
    const normalizedCurrency = (currency || "ZAR").toUpperCase();
    const normalizedPaymentPolicy =
      paymentPolicy === "pay_after_approval"
        ? "pay_after_approval"
        : "pay_before_join";

    if (normalizedIsPaid) {
      if (requiresApproval) {
        return res.status(400).json({
          message: "Paid events cannot require host approval",
        });
      }
      if (
        !Number.isFinite(normalizedPriceAmount) ||
        normalizedPriceAmount <= 0
      ) {
        return res.status(400).json({
          message: "Paid events require a valid priceAmount greater than 0",
        });
      }

      const hostPayoutProfile = await HostPayoutProfile.findOne({
        userId: hostId,
      }).lean();
      if (!hostPayoutProfile || hostPayoutProfile.status !== "active") {
        return res.status(403).json({
          message: "Host payout profile must be active to create paid events",
        });
      }
    }

    const capacityCheck = validateCapacity({
      capacity: capacity ?? 6,
      isPaid: normalizedIsPaid,
    });
    if (!capacityCheck.ok) {
      return res.status(400).json({ message: capacityCheck.message });
    }
    const normalizedCapacity = capacityCheck.value;

    // Check if this is a suggestion (single or group)
    const isGroupSuggestion =
      status === "suggested" &&
      Array.isArray(suggestedToUserIds) &&
      suggestedToUserIds.length > 0;
    const isSingleSuggestion =
      status === "suggested" && suggestedToUserId && !isGroupSuggestion;
    const isSuggestion = isGroupSuggestion || isSingleSuggestion;

    // Validate target users for suggestions
    let targetUsers = [];
    if (isGroupSuggestion) {
      targetUsers = await User.find({
        _id: { $in: suggestedToUserIds },
      }).select("_id name gender profileImages");
      if (targetUsers.length !== suggestedToUserIds.length) {
        return res
          .status(404)
          .json({ message: "One or more suggested users not found" });
      }
    } else if (isSingleSuggestion) {
      const targetUser = await User.findById(suggestedToUserId);
      if (!targetUser) {
        return res.status(404).json({ message: "Suggested user not found" });
      }
      targetUsers = [targetUser];
    }

    // Validate suggested users' genders match the audience
    if (isSuggestion && audience && audience !== "everyone") {
      const genderMap = { women_only: "female", men_only: "male" };
      const requiredGender = genderMap[audience];
      if (requiredGender) {
        const mismatch = targetUsers.find((u) => u.gender !== requiredGender);
        if (mismatch) {
          return res.status(400).json({
            message: `Can't suggest a ${audience === "women_only" ? "women-only" : "men-only"} event to ${mismatch.name}`,
          });
        }
      }
    }

    // Create the event
    const newEvent = new Event({
      hostId,
      title,
      description,
      location: {
        type: "Point",
        coordinates: location.coordinates,
        name: location.name,
        address: location.address,
      },
      coverImage,
      link: normalizedLink,
      startTime: new Date(startTime),
      endTime: endTime ? new Date(endTime) : null,
      capacity: normalizedCapacity,
      tags: tags || [],
      audience: audience || "everyone",
      requiresApproval: normalizedIsPaid ? false : !!requiresApproval,
      isPaid: normalizedIsPaid,
      priceAmount: normalizedIsPaid ? Math.round(normalizedPriceAmount) : 0,
      currency: normalizedCurrency,
      paymentPolicy: normalizedIsPaid
        ? "pay_before_join"
        : normalizedPaymentPolicy,
      participants: isSuggestion
        ? []
        : [
            {
              userId: hostId,
              status: "going",
              joinedAt: new Date(),
            },
          ],
      status: isSuggestion ? "suggested" : "upcoming",
      suggestedToUserId: isSingleSuggestion ? suggestedToUserId : undefined,
      suggestedToUserIds: isGroupSuggestion ? suggestedToUserIds : undefined,
      expiresAt: isSuggestion && expiresAt ? new Date(expiresAt) : undefined,
    });

    await newEvent.save();

    if (!isSuggestion) {
      await User.findByIdAndUpdate(hostId, { $inc: { eventsHosted: 1 } });
      await incrementMissionStats({ tablesCreatedDelta: 1 });
    }

    // Populate host info for response (wrap in try-catch to ensure response is sent)
    let populatedEvent;
    try {
      populatedEvent = await Event.findById(newEvent._id).populate(
        "hostId",
        "name profileImages",
      );
    } catch (populateError) {
      console.error("Error populating event:", populateError);
      // If populate fails, use the event without population
      populatedEvent = newEvent;
    }

    // Send success response immediately after event is created
    const suggestionCount = targetUsers.length;
    res.status(201).json({
      message: isSuggestion
        ? suggestionCount > 1
          ? `Activity suggestion sent to ${suggestionCount} people`
          : "Activity suggestion sent"
        : "Event created successfully",
      event: populatedEvent,
    });

    // Handle notifications after response is sent
    setImmediate(async () => {
      try {
        if (isSuggestion && targetUsers.length > 0) {
          // Send notification to all suggested users
          for (const targetUser of targetUsers) {
            try {
              await createNotificationWithCaps({
                userId: targetUser._id,
                type: "activity_suggestion",
                title: "Activity Suggestion",
                message: isGroupSuggestion
                  ? `${host.name} invited you and ${suggestionCount - 1} others to "${title}"`
                  : `${host.name} wants to do "${title}" with you`,
                eventId: newEvent._id,
                eventName: title,
                actorId: hostId,
                actorName: host.name,
                actorImage: host.profileImages?.[0],
              });
              console.log(
                `[Suggestion] Sent activity suggestion notification to ${targetUser.name}`,
              );
            } catch (notifError) {
              console.error(
                `Error creating suggestion notification for user ${targetUser._id}:`,
                notifError,
              );
            }
          }
          console.log(
            `[Suggestion] Completed sending ${suggestionCount} suggestion notifications`,
          );
        } else {
          // Regular event - notify nearby users (within 50km)
          if (process.env.REDIS_URL && getQueue()) {
            enqueueNearbyEvent(newEvent._id);
            console.log(
              `[Event Nearby] Enqueued event_nearby for event ${newEvent._id}`,
            );
          } else {
            const [eventLng, eventLat] = location.coordinates;
            const maxDistanceMeters = 50000; // 50km
            const audienceQuery = {};
            if (newEvent.audience === "women_only")
              audienceQuery.gender = "female";
            else if (newEvent.audience === "men_only")
              audienceQuery.gender = "male";
            const recentlyNotifiedInline = (
              await getRecentlyNotifiedUserIds(
                "event_nearby",
                DISCOVERY_COOLDOWN_MS,
              )
            ).map((id) => new mongoose.Types.ObjectId(id));
            // Tier A: prefer users who haven't received event_nearby in the cooldown window.
            const tierAUsers = await User.aggregate([
              {
                $geoNear: {
                  near: { type: "Point", coordinates: [eventLng, eventLat] },
                  distanceField: "distance",
                  maxDistance: maxDistanceMeters,
                  spherical: true,
                  query: {
                    $and: [
                      { _id: { $ne: new mongoose.Types.ObjectId(hostId) } },
                      ...(recentlyNotifiedInline.length
                        ? [{ _id: { $nin: recentlyNotifiedInline } }]
                        : []),
                      { pushToken: { $exists: true, $ne: null } },
                      ...(audienceQuery.gender
                        ? [{ gender: audienceQuery.gender }]
                        : []),
                      ...EVENTS_ONLY_QUERY.$and,
                    ],
                  },
                },
              },
              { $sample: { size: NEARBY_NOTIFY_LIMIT } },
              { $project: { _id: 1, name: 1 } },
            ]);

            let nearbyUsers = tierAUsers;

            // Tier B fallback: if the fresh pool is too small, fill from recently-notified users so we never hit 0 recipients.
            if (
              nearbyUsers.length < MIN_FRESH_RECIPIENTS &&
              recentlyNotifiedInline.length > 0
            ) {
              const remaining = Math.max(
                0,
                NEARBY_NOTIFY_LIMIT - nearbyUsers.length,
              );
              if (remaining > 0) {
                const tierBUsers = await User.aggregate([
                  {
                    $geoNear: {
                      near: {
                        type: "Point",
                        coordinates: [eventLng, eventLat],
                      },
                      distanceField: "distance",
                      maxDistance: maxDistanceMeters,
                      spherical: true,
                      query: {
                        $and: [
                          { _id: { $ne: new mongoose.Types.ObjectId(hostId) } },
                          { _id: { $in: recentlyNotifiedInline } },
                          { pushToken: { $exists: true, $ne: null } },
                          ...(audienceQuery.gender
                            ? [{ gender: audienceQuery.gender }]
                            : []),
                          ...EVENTS_ONLY_QUERY.$and,
                        ],
                      },
                    },
                  },
                  { $sample: { size: remaining } },
                  { $project: { _id: 1, name: 1 } },
                ]);
                nearbyUsers = [...nearbyUsers, ...tierBUsers];
              }
            }
            console.log(
              `[Event Nearby] Found ${nearbyUsers.length} users near new event "${title}"`,
            );
            const eventNearbyStr = getStrings("en").eventNearby;
            const spotsOpen = Math.max(0, (newEvent.capacity || 6) - 1);
            for (const nearbyUser of nearbyUsers) {
              try {
                const notifTitle = interpolate(eventNearbyStr.title, {});
                const notifBody = interpolate(eventNearbyStr.body, {
                  name: host.name,
                  activity: title,
                  spotsOpen: String(spotsOpen),
                });
                await createNotificationWithCaps({
                  userId: nearbyUser._id,
                  type: "event_nearby",
                  title: notifTitle,
                  message: notifBody,
                  eventId: newEvent._id,
                  eventName: title,
                  actorId: hostId,
                  actorName: host.name,
                });
              } catch (notifError) {
                console.error(
                  `Error creating nearby notification for user ${nearbyUser._id}:`,
                  notifError,
                );
              }
            }
          }
        }
      } catch (notifyError) {
        console.error("Error sending notifications:", notifyError);
      }
    });
  } catch (error) {
    console.error("Error creating event:", error);
    if (error.status) {
      return res.status(error.status).json({ message: error.message });
    }
    res.status(500).json({
      message: "Error creating event",
      error: error.message,
    });
  }
});

// Update event (host only)
app.put("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;
    const {
      userId,
      title,
      description,
      startTime,
      endTime,
      capacity,
      tags,
      coverImage,
      link,
      audience,
      requiresApproval,
      isPaid,
      priceAmount,
      currency,
      paymentPolicy,
    } = req.body;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if user is the host
    if (event.hostId.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Only the host can update this event" });
    }

    // Don't allow updates to ended or cancelled events
    if (event.status === "ended" || event.status === "cancelled") {
      return res
        .status(400)
        .json({ message: "Cannot update ended or cancelled events" });
    }

    // Validate audience change against host gender and participant genders
    if (audience && audience !== event.audience) {
      const host = await User.findById(userId).select("gender");
      if (audience === "women_only" && host.gender !== "female") {
        return res
          .status(400)
          .json({ message: "Only women can host women-only events" });
      }
      if (audience === "men_only" && host.gender !== "male") {
        return res
          .status(400)
          .json({ message: "Only men can host men-only events" });
      }

      const genderMap = { women_only: "female", men_only: "male" };
      const requiredGender = genderMap[audience];
      if (requiredGender && event.participants.length > 0) {
        await event.populate("participants.userId", "gender");
        const mismatch = event.participants.some(
          (p) => p.userId?.gender !== requiredGender,
        );
        if (mismatch) {
          return res.status(400).json({
            message:
              "Can't change audience — some participants don't match this gender group",
          });
        }
      }
    }

    const nextIsPaid =
      typeof isPaid === "boolean" ? isPaid : event.isPaid;

    if (
      typeof isPaid === "boolean" &&
      !isPaid &&
      event.capacity > FREE_EVENT_MAX_CAPACITY
    ) {
      return res.status(400).json({
        message: `Reduce capacity to ${FREE_EVENT_MAX_CAPACITY} or fewer before making this a free event`,
      });
    }

    if (capacity !== undefined && capacity !== null) {
      const capacityCheck = validateCapacity({
        capacity,
        isPaid: nextIsPaid,
      });
      if (!capacityCheck.ok) {
        return res.status(400).json({ message: capacityCheck.message });
      }
      const occupied = countOccupiedSeats(event);
      if (capacityCheck.value < occupied) {
        return res.status(400).json({
          message: `Capacity cannot be less than current attendees (${occupied})`,
        });
      }
      event.capacity = capacityCheck.value;
      event.status = computeNextEventStatus(event);
    }

    // Update allowed fields
    if (title) event.title = title;
    if (description !== undefined) event.description = description;
    if (startTime) event.startTime = new Date(startTime);
    if (endTime) event.endTime = new Date(endTime);
    if (tags) event.tags = tags;
    if (coverImage !== undefined) {
      const prevCover = event.coverImage;
      if (prevCover && prevCover !== coverImage) {
        const oldKey = keyFromPublicUrl(prevCover);
        if (oldKey) {
          try {
            await deleteObjectFromR2(oldKey);
          } catch (e) {
            console.warn(
              "[Event Update] R2 delete old cover failed:",
              e?.message,
            );
          }
        }
      }
      event.coverImage = coverImage || null;
    }
    if (link !== undefined) {
      const trimmed =
        link != null && String(link).trim() ? String(link).trim() : null;
      if (trimmed && !/^https?:\/\//i.test(trimmed)) {
        return res.status(400).json({
          message: "link must be a valid http(s) URL",
        });
      }
      event.link = trimmed;
    }
    if (audience && ["everyone", "women_only", "men_only"].includes(audience)) {
      event.audience = audience;
    }
    if (nextIsPaid && requiresApproval === true) {
      return res.status(400).json({
        message: "Paid events cannot require host approval",
      });
    }
    if (typeof requiresApproval === "boolean" && !nextIsPaid) {
      event.requiresApproval = requiresApproval;
    }
    if (typeof isPaid === "boolean") {
      if (isPaid) {
        const normalizedPriceAmount = Number(priceAmount ?? event.priceAmount);
        if (
          !Number.isFinite(normalizedPriceAmount) ||
          normalizedPriceAmount <= 0
        ) {
          return res.status(400).json({
            message: "Paid events require a valid priceAmount greater than 0",
          });
        }
        const hostPayoutProfile = await HostPayoutProfile.findOne({
          userId,
        }).lean();
        if (!hostPayoutProfile || hostPayoutProfile.status !== "active") {
          return res.status(403).json({
            message: "Host payout profile must be active to enable paid events",
          });
        }
        event.isPaid = true;
        event.priceAmount = Math.round(normalizedPriceAmount);
        event.currency = (currency || event.currency || "ZAR").toUpperCase();
        event.requiresApproval = false;
        event.paymentPolicy = "pay_before_join";
      } else {
        event.isPaid = false;
        event.priceAmount = 0;
      }
    } else {
      if (priceAmount !== undefined && event.isPaid) {
        const normalizedPriceAmount = Number(priceAmount);
        if (
          !Number.isFinite(normalizedPriceAmount) ||
          normalizedPriceAmount <= 0
        ) {
          return res.status(400).json({
            message: "Paid events require a valid priceAmount greater than 0",
          });
        }
        event.priceAmount = Math.round(normalizedPriceAmount);
      }
      if (currency && event.isPaid) {
        event.currency = String(currency).toUpperCase();
      }
    }
    if (typeof websiteVisible === "boolean") {
      event.websiteVisible = websiteVisible;
    }
    if (event.isPaid) {
      event.requiresApproval = false;
      event.paymentPolicy = "pay_before_join";
    }

    await event.save();

    // Notify all participants (except host) about the update
    const participantIds = event.participants
      .map((p) => {
        const participantUserId = p?.userId?._id || p?.userId;
        return participantUserId?.toString();
      })
      .filter(Boolean)
      .filter((id) => id !== userId);

    for (const participantId of participantIds) {
      try {
        await createNotificationWithCaps({
          userId: participantId,
          type: "event_updated",
          title: "Event updated",
          message: `"${event.title}" has been updated by the host`,
          eventId: event._id,
          eventName: event.title,
        });
      } catch (notifError) {
        console.error("Error creating update notification:", notifError);
      }
    }

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    res.status(200).json({
      message: "Event updated successfully",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error updating event:", error);
    res.status(500).json({
      message: "Error updating event",
      error: error.message,
    });
  }
});

// Cancel/Delete event (host only)
app.delete("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId } = req.body;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if user is the host
    if (event.hostId.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Only the host can cancel this event" });
    }

    // Store event info for notifications before deletion
    const eventTitle = event.title;
    const participantIds = event.participants
      .map((p) => p.userId.toString())
      .filter((id) => id !== userId);
    const refundSummary = {
      attempted: 0,
      successful: 0,
      failed: 0,
      skipped: 0,
      results: [],
    };

    if (event.isPaid) {
      const paidPayments = await EventPayment.find({
        eventId: event._id,
        status: "paid",
      })
        .sort({ paidAt: -1, createdAt: -1 })
        .lean();
      console.log("[EventCancel][Refund] Paid event cancellation refund scan", {
        eventId: event._id?.toString(),
        hostUserId: userId,
        paidRecords: paidPayments.length,
      });

      // Refund each participant at most once (latest paid record per user).
      const latestPaidByUser = new Map();
      for (const payment of paidPayments) {
        const participantId = String(payment.userId);
        if (!latestPaidByUser.has(participantId)) {
          latestPaidByUser.set(participantId, payment);
        }
      }

      for (const [participantId, payment] of latestPaidByUser.entries()) {
        refundSummary.attempted += 1;
        console.log(
          "[EventCancel][Refund] Attempting full refund (host cancel)",
          {
            eventId: event._id?.toString(),
            participantId,
            reference: payment.providerReference,
            amountPaid: payment.amount,
            baseAmount: payment.baseAmount,
          },
        );
        try {
          const refund = await createRefund({
            eventId: event._id.toString(),
            reference: payment.providerReference,
            requesterUserId: userId,
            refundType: "full",
            reason: "Host cancelled paid event",
          });
          refundSummary.successful += 1;
          console.log("[EventCancel][Refund] Refund success", {
            eventId: event._id?.toString(),
            participantId,
            reference: payment.providerReference,
            refundedAmount: refund?.amount || 0,
          });
          refundSummary.results.push({
            userId: participantId,
            reference: payment.providerReference,
            status: "refunded",
            amount: refund?.amount || 0,
          });
        } catch (refundError) {
          const message = String(refundError?.message || "");
          if (
            message.includes("Only paid payments can be refunded") ||
            message.includes("Payment not found")
          ) {
            refundSummary.skipped += 1;
            console.log("[EventCancel][Refund] Refund skipped", {
              eventId: event._id?.toString(),
              participantId,
              reference: payment.providerReference,
              reason: message,
            });
            refundSummary.results.push({
              userId: participantId,
              reference: payment.providerReference,
              status: "skipped",
              reason: message,
            });
          } else {
            refundSummary.failed += 1;
            console.error("[EventCancel][Refund] Refund failed", {
              eventId: event._id?.toString(),
              participantId,
              reference: payment.providerReference,
              reason: message || "Refund failed",
            });
            refundSummary.results.push({
              userId: participantId,
              reference: payment.providerReference,
              status: "failed",
              reason: message || "Refund failed",
            });
          }
        }
      }
    }

    // Notify all participants (except host) about cancellation before deleting
    for (const participantId of participantIds) {
      try {
        await createNotificationWithCaps({
          userId: participantId,
          type: "event_cancelled",
          title: "Event cancelled",
          message: `The event "${eventTitle}" has been cancelled`,
          eventId: event._id,
          eventName: eventTitle,
        });
      } catch (notifError) {
        console.error("Error creating cancel notification:", notifError);
      }
    }

    // Delete all event chat messages
    try {
      const deleteMessagesResult = await EventMessage.deleteMany({ eventId });
      console.log(
        `[Event Delete] Deleted ${deleteMessagesResult.deletedCount} messages for event ${eventId}`,
      );
    } catch (messageError) {
      console.error("Error deleting event messages:", messageError);
    }

    const coverUrlForR2 = event.coverImage;

    // Delete the event itself
    await Event.findByIdAndDelete(eventId);

    await deleteEventCoverImageFromR2(coverUrlForR2);

    console.log(`[Event Delete] Successfully deleted event ${eventId}`);

    res.status(200).json({
      message: "Event cancelled and deleted successfully",
      refunds: refundSummary,
    });
    console.log("[EventCancel] Completed cancellation with refund summary", {
      eventId,
      hostUserId: userId,
      refunds: refundSummary,
    });
  } catch (error) {
    console.error("Error cancelling event:", error);
    res.status(500).json({
      message: "Error cancelling event",
      error: error.message,
    });
  }
});

// Get nearby events
app.get("/events/nearby", async (req, res) => {
  try {
    const { latitude, longitude, radius = 50000, userId, gender } = req.query;

    if (!latitude || !longitude) {
      return res.status(400).json({
        message: "Latitude and longitude are required",
      });
    }

    const parsedLat = parseFloat(latitude);
    const parsedLng = parseFloat(longitude);
    const parsedRadius = parseInt(radius);

    if (isNaN(parsedLat) || isNaN(parsedLng)) {
      return res.status(400).json({ message: "Invalid coordinates format" });
    }

    // Get blocked users list and user gender if userId provided
    let blockedUserIds = [];
    let userGender = gender || null;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const currentUser =
        await User.findById(userId).select("blockedBy gender");
      if (currentUser) {
        blockedUserIds = currentUser.blockedBy.map((id) => id.toString());
        if (!userGender) userGender = currentUser.gender;
      }
    }

    // Build audience filter based on user gender
    const audienceFilter = [];
    audienceFilter.push({ audience: { $exists: false } });
    audienceFilter.push({ audience: "everyone" });
    if (userGender === "female") {
      audienceFilter.push({ audience: "women_only" });
    } else if (userGender === "male") {
      audienceFilter.push({ audience: "men_only" });
    }

    const nearbyEvents = await Event.aggregate([
      {
        $geoNear: {
          near: {
            type: "Point",
            coordinates: [parsedLng, parsedLat],
          },
          distanceField: "distance",
          maxDistance: parsedRadius,
          spherical: true,
          query: {
            status: { $in: ["upcoming", "live", "full"] },
            hostId: {
              $nin: blockedUserIds.map((id) => new mongoose.Types.ObjectId(id)),
            },
            $or: audienceFilter,
          },
          distanceMultiplier: 0.001, // Convert to km
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "hostId",
          foreignField: "_id",
          as: "host",
          pipeline: [{ $project: { name: 1, profileImages: 1 } }],
        },
      },
      {
        $unwind: "$host",
      },
      {
        $addFields: {
          participantCount: { $size: "$participants" },
        },
      },
      {
        $sort: { startTime: 1 },
      },
      {
        $limit: 50,
      },
      // Map / home tab only needs a small slice of each event (see ios-events EventMapMarker, EventPreviewCard compact, list fallback). Near You tab also consumes this payload (cover image, tags, paid flag, createdAt for "Just posted").
      {
        $project: {
          _id: 1,
          title: 1,
          description: 1,
          startTime: 1,
          endTime: 1,
          capacity: 1,
          status: 1,
          audience: 1,
          distance: 1,
          participantCount: 1,
          tags: 1,
          coverImage: 1,
          isPaid: 1,
          priceAmount: 1,
          currency: 1,
          createdAt: 1,
          location: {
            type: "$location.type",
            coordinates: "$location.coordinates",
            name: "$location.name",
          },
          participants: {
            $map: {
              input: { $ifNull: ["$participants", []] },
              as: "p",
              in: {
                userId: "$$p.userId",
                status: "$$p.status",
              },
            },
          },
          host: {
            name: "$host.name",
            profileImages: "$host.profileImages",
          },
        },
      },
    ]);

    const eventsWithStatus = nearbyEvents
      .map((e) => ({
        ...e,
        status: computeNextEventStatus(e),
      }))
      .filter((e) => e.status !== "ended" && e.status !== "cancelled");

    res.status(200).json({
      message: "Nearby events found",
      events: eventsWithStatus,
      count: eventsWithStatus.length,
    });
  } catch (error) {
    console.error("Error fetching nearby events:", error);
    res.status(500).json({
      message: "Error fetching nearby events",
      error: error.message,
    });
  }
});

// Search events by title/tags
app.get("/events/search", async (req, res) => {
  try {
    const {
      q,
      tags,
      latitude,
      longitude,
      userId,
      gender,
      page = 1,
      limit = 20,
    } = req.query;

    const query = {
      status: { $in: ["upcoming", "live", "full"] },
    };

    // Search by title or description
    if (q) {
      query.$or = [
        { title: { $regex: q, $options: "i" } },
        { description: { $regex: q, $options: "i" } },
        { "location.name": { $regex: q, $options: "i" } },
      ];
    }

    // Filter by tags
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(",");
      query.tags = { $in: tagArray };
    }

    // Exclude blocked users and apply audience filter
    let userGender = gender || null;
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      const currentUser =
        await User.findById(userId).select("blockedBy gender");
      if (currentUser) {
        if (currentUser.blockedBy.length > 0) {
          query.hostId = { $nin: currentUser.blockedBy };
        }
        if (!userGender) userGender = currentUser.gender;
      }
    }

    // Audience filter
    const audienceFilter = [
      { audience: { $exists: false } },
      { audience: "everyone" },
    ];
    if (userGender === "female") {
      audienceFilter.push({ audience: "women_only" });
    } else if (userGender === "male") {
      audienceFilter.push({ audience: "men_only" });
    }
    query.$and = [{ $or: audienceFilter }];
    if (query.$or) {
      query.$and.push({ $or: query.$or });
      delete query.$or;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    let events;

    // If location provided, sort by distance
    if (latitude && longitude) {
      const parsedLat = parseFloat(latitude);
      const parsedLng = parseFloat(longitude);

      events = await Event.aggregate([
        {
          $geoNear: {
            near: {
              type: "Point",
              coordinates: [parsedLng, parsedLat],
            },
            distanceField: "distance",
            spherical: true,
            query: query,
            distanceMultiplier: 0.001,
          },
        },
        { $skip: skip },
        { $limit: parseInt(limit) },
        {
          $lookup: {
            from: "users",
            localField: "hostId",
            foreignField: "_id",
            as: "host",
            pipeline: [{ $project: { name: 1, profileImages: 1 } }],
          },
        },
        { $unwind: "$host" },
      ]);
    } else {
      events = await Event.find(query)
        .populate("hostId", "name profileImages")
        .sort({ startTime: 1 })
        .skip(skip)
        .limit(parseInt(limit));
    }

    const total = await Event.countDocuments(query);

    res.status(200).json({
      events,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error searching events:", error);
    res.status(500).json({
      message: "Error searching events",
      error: error.message,
    });
  }
});

// Get user's events (hosting + joined)
app.get("/events/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { type = "all" } = req.query; // 'hosting', 'joined', 'all'

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    let query = {};

    if (type === "hosting") {
      query = { hostId: userId };
    } else if (type === "joined") {
      query = {
        "participants.userId": userId,
        hostId: { $ne: userId },
      };
    } else {
      query = {
        $or: [{ hostId: userId }, { "participants.userId": userId }],
      };
    }

    const events = await Event.find(query)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages")
      .sort({ startTime: -1 });

    // Update statuses
    for (let event of events) {
      await updateEventStatus(event);
    }

    res.status(200).json({
      events,
      count: events.length,
    });
  } catch (error) {
    console.error("Error fetching user events:", error);
    res.status(500).json({
      message: "Error fetching user events",
      error: error.message,
    });
  }
});

const hasUserInList = (list = [], targetUserId) => {
  const normalizedTarget = targetUserId?.toString();
  if (!normalizedTarget) return false;
  return list.some((entry) => {
    const rawUserId = entry?.userId?._id || entry?.userId || entry;
    return rawUserId?.toString() === normalizedTarget;
  });
};

const PAYMENT_HOLD_MS = 2 * 60 * 60 * 1000;

const promoteNextWaitlistedUser = async (event) => {
  if (event.requiresApproval) {
    return { handled: false, promoted: false };
  }

  if (!Array.isArray(event.waitlist)) {
    event.waitlist = [];
  }

  if (!Array.isArray(event.joinRequests)) {
    event.joinRequests = [];
  }

  const hostUser = await User.findById(event.hostId)
    .select("name blockedBy")
    .lean();
  const genderMap = { women_only: "female", men_only: "male" };
  let promotedUser = null;

  while (event.waitlist.length > 0) {
    const nextInLine = event.waitlist.shift();
    const candidateUserId =
      nextInLine?.userId?._id || nextInLine?.userId || nextInLine;
    const normalizedCandidateUserId = candidateUserId?.toString();

    if (!normalizedCandidateUserId) continue;
    if (!mongoose.Types.ObjectId.isValid(normalizedCandidateUserId)) continue;
    if (hasUserInList(event.participants, normalizedCandidateUserId)) continue;
    if (hasUserInList(event.joinRequests, normalizedCandidateUserId)) continue;

    const candidate = await User.findById(normalizedCandidateUserId)
      .select("name gender profileImages")
      .lean();
    if (!candidate) continue;
    if (!candidate.profileImages || candidate.profileImages.length === 0)
      continue;

    if (event.audience && event.audience !== "everyone") {
      if (candidate.gender !== genderMap[event.audience]) continue;
    }

    const blockedByHost = (hostUser?.blockedBy || []).some(
      (blockedId) => blockedId?.toString() === normalizedCandidateUserId,
    );
    if (blockedByHost) continue;

    const capWait = event.capacity != null ? event.capacity : 6;
    if (countOccupiedSeats(event) >= capWait) {
      break;
    }

    event.participants.push({
      userId: normalizedCandidateUserId,
      status: "going",
      joinedAt: new Date(),
    });
    promotedUser = {
      userId: normalizedCandidateUserId,
      name: candidate.name || "Someone",
    };
    break;
  }

  event.status = computeNextEventStatus(event);
  await event.save();

  if (promotedUser) {
    try {
      await createNotificationWithCaps({
        userId: promotedUser.userId,
        type: "event_joined",
        title: "You're in!",
        message: `A spot opened up for "${event.title}" and you've been added from the waitlist.`,
        eventId: event._id,
        eventName: event.title,
        actorId: event.hostId,
        actorName: hostUser?.name,
      });
    } catch (notifError) {
      console.error(
        "Error sending waitlist promotion notification:",
        notifError,
      );
    }
  }

  return { handled: true, promoted: !!promotedUser, promotedUser };
};

// Join event
app.post("/events/:eventId/join", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, status = "interested" } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const joiningUser = await User.findById(userId).select(
      "name gender profileImages",
    );
    if (!joiningUser) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!joiningUser.profileImages || joiningUser.profileImages.length === 0) {
      return res.status(400).json({
        message: "profile_incomplete",
        detail: "You need a profile photo before joining an activity",
      });
    }

    let event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check audience restriction
    if (event.audience && event.audience !== "everyone") {
      const genderMap = { women_only: "female", men_only: "male" };
      if (joiningUser.gender !== genderMap[event.audience]) {
        return res.status(403).json({ message: "This event is restricted" });
      }
    }

    // Update event status first
    await updateEventStatus(event);

    // Check if event is joinable
    if (event.status === "ended" || event.status === "cancelled") {
      return res
        .status(400)
        .json({ message: "Cannot join ended or cancelled events" });
    }

    // Check if user is already a participant
    if (!Array.isArray(event.participants)) {
      event.participants = [];
    }
    if (!Array.isArray(event.joinRequests)) {
      event.joinRequests = [];
    }
    if (!Array.isArray(event.waitlist)) {
      event.waitlist = [];
    }
    await expirePendingPaidAdmissions(eventId);
    event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }
    if (!Array.isArray(event.participants)) {
      event.participants = [];
    }
    if (!Array.isArray(event.joinRequests)) {
      event.joinRequests = [];
    }
    if (!Array.isArray(event.waitlist)) {
      event.waitlist = [];
    }

    const existingParticipant = event.participants.find((p) =>
      hasUserInList([p], userId),
    );
    if (existingParticipant) {
      const st = existingParticipant.status;
      if (st === "going" || st === "checked_in") {
        const updatedEvent = await Event.findById(eventId)
          .populate("hostId", "name profileImages")
          .populate("participants.userId", "name profileImages")
          .populate("waitlist.userId", "name profileImages");
        return res.status(200).json({
          message: "Successfully joined event",
          event: updatedEvent,
        });
      }
      if (st === "interested" && event.isPaid) {
        const settledPayment = await EventPayment.findOne({
          eventId: event._id,
          userId,
          status: "paid",
        })
          .sort({ paidAt: -1, createdAt: -1 })
          .lean();
        if (settledPayment) {
          const updatedEvent = await Event.findById(eventId)
            .populate("hostId", "name profileImages")
            .populate("participants.userId", "name profileImages")
            .populate("waitlist.userId", "name profileImages");
          return res.status(200).json({
            message: "Successfully joined event",
            event: updatedEvent,
          });
        }
        return res.status(402).json({
          message: "Payment required before joining this event",
          code: "payment_required",
        });
      }
      return res
        .status(400)
        .json({ message: "You have already joined this event" });
    }

    const existingRequest = event.joinRequests.find((r) =>
      hasUserInList([r], userId),
    );
    if (existingRequest) {
      return res
        .status(400)
        .json({ message: "You have already requested to join this event" });
    }

    const existingWaitlistEntry = event.waitlist.find((w) =>
      hasUserInList([w], userId),
    );
    if (existingWaitlistEntry) {
      return res.status(400).json({
        message: "You are already on the waitlist for this event",
        waitlisted: true,
      });
    }

    const isHostSelfJoin = event.hostId.toString() === userId;

    // Paid events without host approval require payment before join (not for host).
    if (event.isPaid && !event.requiresApproval && !isHostSelfJoin) {
      const settledPayment = await EventPayment.findOne({
        eventId: event._id,
        userId,
        status: "paid",
      })
        .sort({ paidAt: -1, createdAt: -1 })
        .lean();

      if (!settledPayment) {
        return res.status(402).json({
          message: "Payment required before joining this event",
          code: "payment_required",
        });
      }
    }

    // Check if user is blocked by host
    const host = await User.findById(event.hostId).select(
      "blockedBy preferredLanguage",
    );
    const blockedByHost = (host?.blockedBy || []).some(
      (blockedId) => blockedId.toString() === userId,
    );
    if (blockedByHost) {
      return res.status(403).json({ message: "You cannot join this event" });
    }

    if (event.status === "full") {
      if (event.requiresApproval) {
        return res.status(400).json({ message: "Event is full" });
      }

      event.waitlist.push({
        userId,
        createdAt: new Date(),
      });
      await event.save();

      return res.status(200).json({
        message: "Added to waitlist",
        waitlisted: true,
        waitlistPosition: event.waitlist.length,
      });
    }

    // If event requires host approval, create a join request instead of adding participant
    if (event.requiresApproval && !isHostSelfJoin) {
      event.joinRequests.push({
        userId,
        createdAt: new Date(),
      });

      await event.save();

      // Notify host about the join request
      try {
        await createNotificationWithCaps({
          userId: event.hostId,
          type: "event_join_request",
          title: `${joiningUser.name} requested to join your event`,
          message: `${joiningUser.name} wants to join "${event.title}".`,
          eventId: event._id,
          eventName: event.title,
          actorId: userId,
          actorName: joiningUser.name,
          actorImage: joiningUser.profileImages?.[0],
        });
        console.log(
          `[JoinRequest] Created event_join_request notification for host=${event.hostId} from user=${userId} on event=${event._id}`,
        );
      } catch (notifError) {
        console.error("Error creating join request notification:", notifError);
      }

      return res.status(200).json({
        message: "Join request sent",
      });
    }

    // Add user as participant directly when approval is not required
    event.participants.push({
      userId,
      status: status,
      joinedAt: new Date(),
    });

    // Update event status if now full (paid events count payment-hold `interested`)
    const goingCount = event.participants.filter(
      (p) => p.status === "going" || p.status === "checked_in",
    ).length;
    const occupiedAfterJoin = countOccupiedSeats(event);
    const capacityJoin = event.capacity != null ? event.capacity : 6;
    if (occupiedAfterJoin >= capacityJoin) {
      event.status = "full";
    }

    await event.save();

    // Create notification for host (stored in DB + push notification)
    const isFirstJoin = goingCount === 2;
    try {
      const hostLang = host?.preferredLanguage;
      const str =
        hostLang && getStrings(hostLang).firstJoin
          ? getStrings(hostLang).firstJoin
          : getStrings("en").firstJoin;
      const title = isFirstJoin
        ? interpolate(str.title, {})
        : "New participant joined";
      const message = isFirstJoin
        ? interpolate(str.body, { name: joiningUser.name })
        : `${joiningUser.name} joined your event "${event.title}"`;
      await createNotificationWithCaps({
        userId: event.hostId,
        type: "event_joined",
        title,
        message,
        eventId: event._id,
        eventName: event.title,
        actorId: userId,
        actorName: joiningUser.name,
      });
    } catch (notifError) {
      console.error("Error creating join notification:", notifError);
    }

    // When event first reaches 60% capacity: notify host + nearby users who haven't joined (plan: table heating up / filling fast)
    const atSixtyPercent =
      event.capacity > 0 && goingCount / event.capacity >= 0.6;
    if (atSixtyPercent && !event.sixtyPercentNotifSent) {
      try {
        const hostForNotif = await User.findById(event.hostId)
          .select("name preferredLanguage")
          .lean();
        const taken = goingCount;
        const total = event.capacity;
        const left = Math.max(0, total - taken);

        // Host: "Your table is heating up"
        const hostStr =
          hostForNotif?.preferredLanguage &&
          getStrings(hostForNotif.preferredLanguage).table60Full
            ? getStrings(hostForNotif.preferredLanguage).table60Full
            : getStrings("en").table60Full;
        await createNotificationWithCaps({
          userId: event.hostId,
          type: "table_60_full",
          title: hostStr.title,
          message: interpolate(hostStr.body, {
            taken: String(taken),
            total: String(total),
            left: String(left),
          }),
          eventId: event._id,
          eventName: event.title,
        });

        // Nearby users who have NOT joined: "Name's activity is filling up fast" (FOMO cap applies)
        const useQueue = process.env.REDIS_URL && getQueue();
        if (useQueue) {
          enqueueNearby60Fill(event._id);
          console.log(
            `[60% fill] Enqueued event_nearby_60 for event ${event._id}; worker will set sixtyPercentNotifSent`,
          );
        } else {
          const [eventLng, eventLat] = event.location?.coordinates || [];
          const participantIds = event.participants.map((p) => p.userId);
          const excludeIds = [event.hostId, ...participantIds].map((id) =>
            id && id._id ? id._id : id,
          );
          if (eventLng != null && eventLat != null && excludeIds.length > 0) {
            const audienceQuery = {};
            if (event.audience === "women_only")
              audienceQuery.gender = "female";
            else if (event.audience === "men_only")
              audienceQuery.gender = "male";
            const recentlyNotified60Inline = (
              await getRecentlyNotifiedUserIds(
                "table_filling_fast",
                DISCOVERY_COOLDOWN_MS,
              )
            ).map((id) => new mongoose.Types.ObjectId(id));
            const allExcludeIdsInline = [
              ...excludeIds.map((id) =>
                id instanceof mongoose.Types.ObjectId
                  ? id
                  : new mongoose.Types.ObjectId(id),
              ),
              ...recentlyNotified60Inline,
            ];
            const nearbyNotJoined = await User.aggregate([
              {
                $geoNear: {
                  near: { type: "Point", coordinates: [eventLng, eventLat] },
                  distanceField: "distance",
                  maxDistance: 50000,
                  spherical: true,
                  query: {
                    $and: [
                      { _id: { $nin: allExcludeIdsInline } },
                      { pushToken: { $exists: true, $ne: null } },
                      ...(audienceQuery.gender
                        ? [{ gender: audienceQuery.gender }]
                        : []),
                      ...EVENTS_ONLY_QUERY.$and,
                    ],
                  },
                },
              },
              { $sample: { size: NEARBY_NOTIFY_LIMIT } },
              { $project: { _id: 1, preferredLanguage: 1 } },
            ]);
            const fillStrEn = getStrings("en").tableFillingFast;
            const hostName = hostForNotif?.name || "Someone";
            for (const u of nearbyNotJoined) {
              try {
                const str =
                  u.preferredLanguage &&
                  getStrings(u.preferredLanguage).tableFillingFast
                    ? getStrings(u.preferredLanguage).tableFillingFast
                    : fillStrEn;
                const title = interpolate(str.title, {
                  name: hostName,
                  activity: event.title,
                });
                const message = str.body;
                await createNotificationWithCaps({
                  userId: u._id,
                  type: "table_filling_fast",
                  title,
                  message,
                  eventId: event._id,
                  eventName: event.title,
                  actorId: event.hostId,
                  actorName: hostName,
                });
              } catch (e) {
                console.error(
                  "[60% fill] Nearby notif failed for user",
                  u._id,
                  e?.message,
                );
              }
            }
            console.log(
              `[60% fill] Notified host + ${nearbyNotJoined.length} nearby users for "${event.title}"`,
            );
          }
          event.sixtyPercentNotifSent = true;
          await event.save();
        }
      } catch (err) {
        console.error(
          "[60% fill] Error sending 60% notifications:",
          err?.message || err,
        );
      }
    }

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages")
      .populate("waitlist.userId", "name profileImages");

    res.status(200).json({
      message: "Successfully joined event",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error joining event:", error);
    if (error.status) {
      return res.status(error.status).json({ message: error.message });
    }
    res.status(500).json({
      message: "Error joining event",
      error: error.message,
    });
  }
});

// TEST helper: create join request by user email (without going through the app client)
app.post("/events/:eventId/join-request-by-email", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid eventId format" });
    }

    const joiningUser = await User.findOne({ email }).select(
      "name gender profileImages",
    );
    if (!joiningUser) {
      return res.status(404).json({ message: "User not found for this email" });
    }

    if (!joiningUser.profileImages || joiningUser.profileImages.length === 0) {
      return res.status(400).json({
        message: "profile_incomplete",
        detail: "User needs a profile photo before joining an activity",
      });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // This helper is specifically for events that require approval
    if (!event.requiresApproval) {
      return res.status(400).json({
        message: "Event does not require host approval for joins",
      });
    }

    const userId = joiningUser._id;

    // Make sure user is not already a participant
    const existingParticipant = event.participants.find((p) =>
      hasUserInList([p], userId),
    );
    if (existingParticipant) {
      return res
        .status(400)
        .json({ message: "User has already joined this event" });
    }

    // Ensure joinRequests array exists
    if (!Array.isArray(event.joinRequests)) {
      event.joinRequests = [];
    }

    // Check for an existing pending request
    const existingRequest = event.joinRequests.find((r) =>
      hasUserInList([r], userId),
    );
    if (existingRequest) {
      return res.status(400).json({
        message: "User has already requested to join this event",
      });
    }

    // Push new join request
    event.joinRequests.push({
      userId,
      createdAt: new Date(),
    });

    await event.save();

    // Notify host about the join request (same as main join route)
    try {
      await createNotificationWithCaps({
        userId: event.hostId,
        type: "event_join_request",
        title: `${joiningUser.name} requested to join your event`,
        message: `${joiningUser.name} wants to join "${event.title}".`,
        eventId: event._id,
        eventName: event.title,
        actorId: userId,
        actorName: joiningUser.name,
        actorImage: joiningUser.profileImages?.[0],
      });
    } catch (notifError) {
      console.error(
        "Error creating join request notification (test helper):",
        notifError,
      );
    }

    return res.status(200).json({
      message: "Test join request created",
      eventId: event._id,
      userId,
      email,
    });
  } catch (error) {
    console.error("Error creating join request by email:", error);
    return res.status(500).json({
      message: "Error creating join request by email",
      error: error.message,
    });
  }
});

// Update RSVP status
app.put("/events/:eventId/rsvp", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, status } = req.body;

    if (!["interested", "going", "checked_in"].includes(status)) {
      return res.status(400).json({
        message: "Invalid status. Must be: interested, going, or checked_in",
      });
    }

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Find participant
    const participantIndex = event.participants.findIndex(
      (p) => p.userId.toString() === userId,
    );
    if (participantIndex === -1) {
      return res
        .status(404)
        .json({ message: "You are not a participant of this event" });
    }

    // Update status
    event.participants[participantIndex].status = status;

    // Update event status if needed
    const occupiedRsvp = countOccupiedSeats(event);
    const capacityRsvp = event.capacity != null ? event.capacity : 6;

    if (occupiedRsvp >= capacityRsvp && event.status !== "ended") {
      event.status = "full";
    } else if (occupiedRsvp < capacityRsvp && event.status === "full") {
      const now = new Date();
      event.status = event.startTime <= now ? "live" : "upcoming";
    }

    await event.save();

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    res.status(200).json({
      message: "RSVP status updated",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error updating RSVP:", error);
    res.status(500).json({
      message: "Error updating RSVP",
      error: error.message,
    });
  }
});

// Check-in to event (validates location)
app.post("/events/:eventId/check-in", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, latitude, longitude } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    if (!latitude || !longitude) {
      return res
        .status(400)
        .json({ message: "Location is required for check-in" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Update event status
    await updateEventStatus(event);

    // Check if event is live
    if (event.status !== "live" && event.status !== "full") {
      return res.status(400).json({
        message: "Check-in is only available for live events",
      });
    }

    // Find participant
    const participantIndex = event.participants.findIndex(
      (p) => (p.userId && p.userId.toString()) === userId,
    );
    if (participantIndex === -1) {
      return res
        .status(404)
        .json({ message: "You are not a participant of this event" });
    }

    // Validate event location
    if (
      !event.location ||
      !event.location.coordinates ||
      event.location.coordinates.length < 2
    ) {
      return res.status(400).json({
        message: "Event location is invalid; check-in is not available.",
      });
    }

    // Calculate distance using existing helper
    const userLat = parseFloat(latitude);
    const userLng = parseFloat(longitude);
    const eventLat = event.location.coordinates[1];
    const eventLng = event.location.coordinates[0];

    const distance = calculateDistance(userLat, userLng, eventLat, eventLng);
    if (distance == null || Number.isNaN(distance)) {
      return res.status(400).json({
        message:
          "Invalid location for check-in. Please ensure location is enabled.",
      });
    }

    const distanceInMeters = distance * 1000;
    const checkInRadius = event.checkInRadius ?? 100;

    if (distanceInMeters > checkInRadius) {
      return res.status(400).json({
        message: `You must be within ${checkInRadius}m of the event location to check in. You are ${Math.round(
          distanceInMeters,
        )}m away.`,
      });
    }

    // Update participant status to checked_in
    event.participants[participantIndex].status = "checked_in";
    await event.save();

    // Persist co-attendee ledger: mutual $addToSet for every other checked-in participant
    const otherCheckedIn = event.participants.filter(
      (p) =>
        p.status === "checked_in" && p.userId && p.userId.toString() !== userId,
    );
    for (const peer of otherCheckedIn) {
      const peerId = peer.userId._id || peer.userId;
      try {
        await User.findByIdAndUpdate(userId, {
          $addToSet: { coAttendees: peerId },
        });
        await User.findByIdAndUpdate(peerId, {
          $addToSet: { coAttendees: userId },
        });
      } catch (coErr) {
        console.error("[Check-in] Error updating coAttendees:", coErr);
      }
    }

    // Notify other participants (in-app + push)
    const otherParticipantIds = event.participants
      .filter((p) => p.userId.toString() !== userId)
      .map((p) => p.userId);
    const otherParticipants = await User.find({
      _id: { $in: otherParticipantIds },
    }).select("_id preferredLanguage");

    const checkedInUser = await User.findById(userId).select("name");

    for (const participant of otherParticipants) {
      try {
        const ciStr =
          getStrings(participant.preferredLanguage).eventCheckin ||
          getStrings("en").eventCheckin;
        const title = interpolate(ciStr.title, {
          name: checkedInUser.name,
          eventTitle: event.title,
        });
        const message = interpolate(ciStr.body, {
          name: checkedInUser.name,
          eventTitle: event.title,
        });
        await createNotificationWithCaps({
          userId: participant._id,
          type: "event_checkin",
          title,
          message,
          eventId: event._id,
          eventName: event.title,
          actorId: userId,
          actorName: checkedInUser.name,
        });
      } catch (notifError) {
        console.error("Error sending notification:", notifError);
      }
    }

    const updatedEvent = await Event.findById(eventId)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages");

    res.status(200).json({
      message: "Successfully checked in",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error checking in:", error);
    res.status(500).json({
      message: "Error checking in",
      error: error.message,
    });
  }
});

// Approve a pending join request (host only)
app.post("/events/:eventId/join-requests/:userId/approve", async (req, res) => {
  try {
    const { eventId, userId } = req.params;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    let event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    await expirePendingPaidAdmissions(eventId);
    event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    if (!Array.isArray(event.joinRequests)) {
      event.joinRequests = [];
    }

    const requestIndex = event.joinRequests.findIndex((r) =>
      hasUserInList([r], userId),
    );
    if (requestIndex === -1) {
      return res
        .status(404)
        .json({ message: "Join request not found for this user" });
    }

    // Remove from pending requests
    event.joinRequests.splice(requestIndex, 1);

    const alreadyParticipant = hasUserInList(event.participants, userId);
    const capacityApprove = event.capacity != null ? event.capacity : 6;
    if (!alreadyParticipant && countOccupiedSeats(event) >= capacityApprove) {
      return res.status(400).json({ message: "Event is full" });
    }

    const now = new Date();

    if (!alreadyParticipant) {
      event.participants.push({
        userId,
        status: event.isPaid ? "interested" : "going",
        joinedAt: now,
      });
    }

    if (event.isPaid) {
      const holdExpiresAt = new Date(Date.now() + PAYMENT_HOLD_MS);
      await EventPayment.findOneAndUpdate(
        {
          eventId: event._id,
          userId,
          admissionStatus: "pending_payment",
          status: { $in: ["initialized", "pending"] },
        },
        {
          $setOnInsert: {
            eventId: event._id,
            userId,
            hostId: event.hostId,
            provider: "mock",
            providerReference: `HOLD_${event._id}_${userId}_${Date.now()}`,
            amount: event.priceAmount || 0,
            currency: event.currency || "ZAR",
            baseAmount: event.priceAmount || 0,
            appFeeAmount: 0,
            processingFeeAmount: 0,
            taxAmount: 0,
            quoteId: "",
            providerPayload: { holdOnly: true },
          },
          $set: {
            expiresAt: holdExpiresAt,
            admissionStatus: "pending_payment",
            status: "pending",
          },
        },
        { upsert: true, new: true },
      );
    }

    event.status = computeNextEventStatus(event);
    await event.save();

    // Notify user that they were approved
    try {
      const joiningUser = await User.findById(userId).select("name");
      await createNotificationWithCaps({
        userId,
        type: "event_joined",
        title: event.isPaid ? "Approved - payment pending" : "You're in!",
        message: event.isPaid
          ? `Your request to join "${event.title}" was approved. Complete payment within 2 hours to keep your seat.`
          : `Your request to join "${event.title}" was approved.`,
        eventId: event._id,
        eventName: event.title,
        actorId: event.hostId,
        actorName: joiningUser?.name,
      });
    } catch (notifError) {
      console.error("Error creating join approval notification:", notifError);
    }

    return res.status(200).json({
      message: event.isPaid
        ? "Join request approved. User must pay within 2 hours."
        : "Join request approved",
    });
  } catch (error) {
    console.error("Error approving join request:", error);
    return res
      .status(500)
      .json({ message: "Error approving join request", error: error.message });
  }
});

// Reject a pending join request (host only)
app.post("/events/:eventId/join-requests/:userId/reject", async (req, res) => {
  try {
    const { eventId, userId } = req.params;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    if (!Array.isArray(event.joinRequests)) {
      event.joinRequests = [];
    }

    const requestIndex = event.joinRequests.findIndex((r) =>
      hasUserInList([r], userId),
    );
    if (requestIndex === -1) {
      return res
        .status(404)
        .json({ message: "Join request not found for this user" });
    }

    // Remove from pending requests
    event.joinRequests.splice(requestIndex, 1);

    await event.save();

    // Optionally notify user about rejection
    try {
      await createNotificationWithCaps({
        userId,
        type: "event_join_request_rejected",
        title: "Request declined",
        message: `Your request to join "${event.title}" was declined.`,
        eventId: event._id,
        eventName: event.title,
      });
    } catch (notifError) {
      console.error("Error creating join rejection notification:", notifError);
    }

    return res.status(200).json({ message: "Join request rejected" });
  } catch (error) {
    console.error("Error rejecting join request:", error);
    return res
      .status(500)
      .json({ message: "Error rejecting join request", error: error.message });
  }
});

// Leave event
app.delete("/events/:eventId/leave", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId } = req.body;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Host cannot leave their own event
    if (event.hostId.toString() === userId) {
      return res.status(400).json({
        message: "Host cannot leave the event. Cancel the event instead.",
      });
    }

    const isParticipant = event.participants.some(
      (p) => p.userId.toString() === userId,
    );
    if (!isParticipant) {
      return res
        .status(404)
        .json({ message: "You are not a participant of this event" });
    }

    const now = new Date();
    const startTime =
      event.startTime && !Number.isNaN(new Date(event.startTime).getTime())
        ? new Date(event.startTime)
        : null;
    const msUntilStart = startTime ? startTime.getTime() - now.getTime() : null;
    const eventAlreadyLive =
      event.status === "live" ||
      event.status === "ended" ||
      (msUntilStart != null && msUntilStart <= 0);
    const guestRefundWindowMs = 24 * 60 * 60 * 1000;
    const eligibleEarlyWindow =
      msUntilStart != null && msUntilStart > guestRefundWindowMs;

    let refundEligible = false;
    let refundProcessed = false;
    let refundAmount = 0;
    let refundReason = "not_paid_event";
    let refundReference = "";

    if (event.isPaid) {
      if (eventAlreadyLive) {
        refundReason = "live_no_refund";
      } else if (eligibleEarlyWindow) {
        refundEligible = true;
        refundReason = "outside_24h_refund_window";
      } else {
        refundReason = "within_24h_no_refund";
      }
    }

    if (refundEligible) {
      const payment = await EventPayment.findOne({
        eventId: event._id,
        userId,
        status: "paid",
      })
        .sort({ paidAt: -1, createdAt: -1 })
        .lean();

      if (!payment) {
        refundReason = "no_paid_record";
        console.log("[EventLeave][Refund] Eligible but no paid record found", {
          eventId: event._id?.toString(),
          userId,
        });
      } else {
        refundReference = payment.providerReference || "";
        console.log("[EventLeave][Refund] Attempting ticket-only refund (ticket price)", {
          eventId: event._id?.toString(),
          userId,
          reference: refundReference,
          amountPaid: payment.amount,
          baseAmount: payment.baseAmount,
          appFeeAmount: payment.appFeeAmount,
        });
        try {
          const refundResult = await createRefund({
            eventId: event._id.toString(),
            reference: payment.providerReference,
            requesterUserId: userId,
            refundType: "ticket_only",
            reason: "Attendee left event more than 24 hours before start",
          });
          refundProcessed = true;
          refundAmount = Number(refundResult?.amount) || 0;
          refundReason = "ticket_only_refund_processed";
          console.log("[EventLeave][Refund] Refund success", {
            eventId: event._id?.toString(),
            userId,
            reference: refundReference,
            refundedAmount: refundAmount,
          });
        } catch (refundError) {
          refundReason = String(refundError?.message || "refund_failed");
          console.error("[EventLeave][Refund] Refund failed", {
            eventId: event._id?.toString(),
            userId,
            reference: refundReference,
            reason: refundReason,
          });
        }
      }
    }

    const targetEvent = await Event.findById(eventId);
    if (!targetEvent) {
      return res.status(404).json({ message: "Event not found" });
    }

    const participantStillPresent = (targetEvent.participants || []).some(
      (p) => p?.userId?.toString() === userId,
    );
    if (participantStillPresent) {
      targetEvent.participants = (targetEvent.participants || []).filter(
        (p) => p?.userId?.toString() !== userId,
      );
    }

    if (targetEvent.isPaid) {
      await EventPayment.updateMany(
        {
          eventId: targetEvent._id,
          userId,
          status: { $in: ["initialized", "pending"] },
          admissionStatus: "pending_payment",
        },
        {
          $set: {
            status: "expired",
            admissionStatus: "expired",
          },
        },
      );
    }

    const waitlistResult = await promoteNextWaitlistedUser(targetEvent);
    if (!waitlistResult.handled) {
      if (targetEvent.status === "full") {
        const statusNow = new Date();
        targetEvent.status =
          targetEvent.startTime <= statusNow ? "live" : "upcoming";
      }
      await targetEvent.save();
    }

    res.status(200).json({
      message: "Successfully left event",
      refundEligible,
      refundProcessed,
      refundAmount,
      refundReference,
      refundReason,
      waitlistPromotion: waitlistResult.promoted
        ? { userId: waitlistResult.promotedUser?.userId }
        : null,
    });
    console.log("[EventLeave] Completed leave flow", {
      eventId,
      userId,
      refundEligible,
      refundProcessed,
      refundAmount,
      refundReference,
      refundReason,
    });
  } catch (error) {
    console.error("Error leaving event:", error);
    res.status(500).json({
      message: "Error leaving event",
      error: error.message,
    });
  }
});

// Remove participant (host only)
app.delete("/events/:eventId/participants/:participantId", async (req, res) => {
  try {
    const { eventId, participantId } = req.params;
    const { userId } = req.body; // Host's userId

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(participantId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if requester is the host
    if (event.hostId.toString() !== userId) {
      return res
        .status(403)
        .json({ message: "Only the host can remove participants" });
    }

    // Cannot remove self (host)
    if (participantId === userId) {
      return res
        .status(400)
        .json({ message: "Host cannot be removed from the event" });
    }

    // Find and remove participant
    const participantIndex = event.participants.findIndex(
      (p) => p.userId.toString() === participantId,
    );
    if (participantIndex === -1) {
      return res
        .status(404)
        .json({ message: "Participant not found in this event" });
    }

    event.participants.splice(participantIndex, 1);
    const waitlistResult = await promoteNextWaitlistedUser(event);
    if (!waitlistResult.handled) {
      if (event.status === "full") {
        const now = new Date();
        event.status = event.startTime <= now ? "live" : "upcoming";
      }
      await event.save();
    }

    // Notify removed participant (in-app + push)
    try {
      const removedUser = await User.findById(participantId)
        .select("preferredLanguage")
        .lean();
      const lang = removedUser?.preferredLanguage;
      const removeStr =
        lang && getStrings(lang).eventRemoved
          ? getStrings(lang).eventRemoved
          : getStrings("en").eventRemoved;
      const title = interpolate(removeStr.title, { eventTitle: event.title });
      const message = interpolate(removeStr.body, { eventTitle: event.title });
      await createNotificationWithCaps({
        userId: participantId,
        type: "event_removed",
        title,
        message,
        eventId: event._id,
        eventName: event.title,
      });
    } catch (notifError) {
      console.error("Error sending notification:", notifError);
    }

    res.status(200).json({
      message: "Participant removed successfully",
      waitlistPromotion: waitlistResult.promoted
        ? { userId: waitlistResult.promotedUser?.userId }
        : null,
    });
  } catch (error) {
    console.error("Error removing participant:", error);
    res.status(500).json({
      message: "Error removing participant",
      error: error.message,
    });
  }
});

// Get event chat messages
app.get("/events/:eventId/messages", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, skip = 0, limit = 50 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Check if user is a participant
    if (userId) {
      const isParticipant = event.participants.some(
        (p) => p.userId.toString() === userId,
      );
      if (!isParticipant) {
        return res.status(403).json({
          message: "Only participants can view event messages",
        });
      }
    }

    const messages = await EventMessage.find({ eventId })
      .populate("senderId", "name profileImages")
      .sort({ createdAt: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit));

    res.status(200).json({
      messages: messages.reverse(), // Return in chronological order
      count: messages.length,
    });
  } catch (error) {
    console.error("Error fetching event messages:", error);
    res.status(500).json({
      message: "Error fetching event messages",
      error: error.message,
    });
  }
});

// Get popular tags
app.get("/events/tags/popular", async (req, res) => {
  try {
    const tags = await Event.aggregate([
      { $match: { status: { $in: ["upcoming", "live", "full"] } } },
      { $unwind: "$tags" },
      { $group: { _id: "$tags", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 20 },
    ]);

    res.status(200).json({
      tags: tags.map((t) => ({ tag: t._id, count: t.count })),
    });
  } catch (error) {
    console.error("Error fetching popular tags:", error);
    res.status(500).json({
      message: "Error fetching popular tags",
      error: error.message,
    });
  }
});

// Admin endpoint to get all events
app.get("/admin/events", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      status,
      sortBy = "startTime",
      sortOrder = -1,
    } = req.query;

    const query = {};

    // Filter by status if provided
    if (status && status !== "all") {
      query.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOptions = {};
    sortOptions[sortBy] = parseInt(sortOrder);

    const events = await Event.find(query)
      .populate("hostId", "name profileImages")
      .populate("participants.userId", "name profileImages")
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Event.countDocuments(query);

    res.status(200).json({
      events,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error fetching all events:", error);
    res.status(500).json({
      message: "Error fetching events",
      error: error.message,
    });
  }
});

// Admin endpoint to toggle website visibility without host-only constraints
app.patch("/admin/events/:eventId/website-visibility", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { websiteVisible } = req.body;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    if (typeof websiteVisible !== "boolean") {
      return res
        .status(400)
        .json({ message: "websiteVisible must be a boolean" });
    }

    const updatedEvent = await Event.findByIdAndUpdate(
      eventId,
      { $set: { websiteVisible } },
      { new: true },
    )
      .populate("hostId", "name profileImages")
      .lean();

    if (!updatedEvent) {
      return res.status(404).json({ message: "Event not found" });
    }

    return res.status(200).json({
      message: "Website visibility updated",
      event: updatedEvent,
    });
  } catch (error) {
    console.error("Error updating event website visibility:", error);
    return res.status(500).json({
      message: "Error updating event website visibility",
      error: error.message,
    });
  }
});

app.use("/", ticketRoutes);

// Get event by ID (MUST be after specific routes like /events/nearby, /events/search, etc.)
app.get("/events/:eventId", async (req, res) => {
  try {
    const { eventId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    await expirePendingPaidAdmissions(eventId);

    let event = await Event.findById(eventId)
      .populate("hostId", "name profileImages gender")
      .populate("participants.userId", "name profileImages gender")
      .populate("joinRequests.userId", "name profileImages gender")
      .populate("waitlist.userId", "name profileImages gender");

    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    // Update status if needed
    event = await updateEventStatus(event);

    res.status(200).json(event);
  } catch (error) {
    console.error("Error fetching event:", error);
    res.status(500).json({
      message: "Error fetching event",
      error: error.message,
    });
  }
});

// ============================================================
// NOTIFICATIONS ENDPOINTS
// ============================================================

// Get notifications for a user (paginated)
app.get("/notifications/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Notification.countDocuments({ userId });
    const unreadCount = await Notification.countDocuments({
      userId,
      read: false,
    });

    const joinRequestCount = notifications.filter(
      (n) => n.type === "event_join_request",
    ).length;
    console.log(
      `[NotificationsAPI] user=${userId} page=${page} limit=${limit} -> total=${total}, unread=${unreadCount}, event_join_request=${joinRequestCount}`,
    );

    res.status(200).json({
      notifications,
      total,
      unreadCount,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit)),
    });
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({
      message: "Error fetching notifications",
      error: error.message,
    });
  }
});

// Mark a single notification as read
app.put("/notifications/:notificationId/read", async (req, res) => {
  try {
    const { notificationId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(notificationId)) {
      return res
        .status(400)
        .json({ message: "Invalid notification ID format" });
    }

    const notification = await Notification.findByIdAndUpdate(
      notificationId,
      { read: true },
      { new: true },
    );

    if (!notification) {
      return res.status(404).json({ message: "Notification not found" });
    }

    res.status(200).json({
      message: "Notification marked as read",
      notification,
    });
  } catch (error) {
    console.error("Error marking notification as read:", error);
    res.status(500).json({
      message: "Error marking notification as read",
      error: error.message,
    });
  }
});

// Mark all notifications as read for a user
app.put("/notifications/:userId/read-all", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const result = await Notification.updateMany(
      { userId, read: false },
      { read: true },
    );

    res.status(200).json({
      message: `Marked ${result.modifiedCount} notifications as read`,
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error marking all notifications as read:", error);
    res.status(500).json({
      message: "Error marking notifications as read",
      error: error.message,
    });
  }
});

// Delete a notification
app.delete("/notifications/:notificationId", async (req, res) => {
  try {
    const { notificationId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(notificationId)) {
      return res
        .status(400)
        .json({ message: "Invalid notification ID format" });
    }

    const notification = await Notification.findByIdAndDelete(notificationId);

    if (!notification) {
      return res.status(404).json({ message: "Notification not found" });
    }

    res.status(200).json({
      message: "Notification deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting notification:", error);
    res.status(500).json({
      message: "Error deleting notification",
      error: error.message,
    });
  }
});

// ============================================
// OPEN TAB - People Open to Activities
// ============================================

// Helper function to format active status
const formatActiveStatus = (lastActiveAt) => {
  if (!lastActiveAt) return "Active";

  const now = new Date();
  const lastActive = new Date(lastActiveAt);
  const diffMs = now - lastActive;
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const diffMonths = Math.floor(diffDays / 30);

  if (diffMins < 5) return "Active now";
  if (diffMins < 60) return `Active ${diffMins}m ago`;
  if (diffHours < 24) return `Active ${diffHours}h ago`;
  if (diffDays < 30) return `Active ${diffDays}d ago`;
  return `Active ${diffMonths}mo ago`;
};

// GET /users/nearby/open - Fetch nearby users who are open to activities
app.get("/users/nearby/open", async (req, res) => {
  try {
    const {
      latitude,
      longitude,
      radius = 50000,
      userId,
      limit = 10,
      skip = 0,
      search = "",
    } = req.query;

    if (!latitude || !longitude) {
      return res.status(400).json({
        message: "Latitude and longitude are required",
      });
    }

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        message: "User ID is required",
      });
    }

    const parsedLat = parseFloat(latitude);
    const parsedLng = parseFloat(longitude);

    if (isNaN(parsedLat) || isNaN(parsedLng)) {
      return res.status(400).json({ message: "Invalid coordinates format" });
    }

    const currentUser = await User.findById(userId).select("blockedBy name");

    if (!currentUser) {
      console.log(`❌ [NEARBY/OPEN] User not found: ${userId}`);
      return res.status(404).json({
        message: "User not found",
      });
    }

    const lng = parsedLng;
    const lat = parsedLat;

    const maxDistance = parseInt(radius);
    const queryLimit = Math.min(parseInt(limit) || 10, 50); // Cap at 50
    const querySkip = parseInt(skip) || 0;
    const searchTerm = search.trim();

    // Calculate date 90 days ago
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

    // Build exclusion list (always exclude self + blocked users)
    let excludeIds = [new mongoose.Types.ObjectId(userId)];
    if (currentUser?.blockedBy?.length > 0) {
      excludeIds = excludeIds.concat(currentUser.blockedBy);
    }

    // Build the query conditions
    const queryConditions = [
      // Only show users with showInOpenTab true (or not set, defaulting to true)
      {
        $or: [{ showInOpenTab: { $exists: false } }, { showInOpenTab: true }],
      },
      // Must have been active in last 90 days
      {
        $or: [
          { lastActiveAt: { $gte: ninetyDaysAgo } },
          { updatedAt: { $gte: ninetyDaysAgo } }, // Fallback for users without lastActiveAt
        ],
      },
      // Must have valid location
      { "location.coordinates": { $exists: true, $ne: [0, 0] } },
      // Must have at least one interest
      { interests: { $exists: true, $not: { $size: 0 } } },
      // Must have at least one profile image
      { profileImages: { $exists: true, $not: { $size: 0 } } },
      // Exclude self and blocked users
      ...(excludeIds.length > 0 ? [{ _id: { $nin: excludeIds } }] : []),
    ];

    // Add search filter if provided
    if (searchTerm) {
      queryConditions.push({
        name: { $regex: searchTerm, $options: "i" },
      });
    }

    const pipeline = [
      {
        $geoNear: {
          near: { type: "Point", coordinates: [lng, lat] },
          distanceField: "distance",
          maxDistance: maxDistance,
          spherical: true,
          query: { $and: queryConditions },
        },
      },
      {
        $project: {
          _id: 1,
          name: 1,
          profileImages: { $slice: ["$profileImages", 1] },
          interests: { $slice: ["$interests", 3] },
          distance: { $divide: ["$distance", 1000] }, // Convert to km
          lastActiveAt: 1,
          updatedAt: 1,
        },
      },
      // Sort by recency first (most recent first), then by distance
      {
        $addFields: {
          effectiveLastActive: {
            $ifNull: ["$lastActiveAt", "$updatedAt"],
          },
        },
      },
      { $sort: { effectiveLastActive: -1, distance: 1 } },
      { $skip: querySkip },
      { $limit: queryLimit + 1 }, // Fetch one extra to check if there's more
    ];

    const users = await User.aggregate(pipeline);

    // Check if there are more results
    const hasMore = users.length > queryLimit;
    if (hasMore) {
      users.pop(); // Remove the extra item
    }

    // Format the response
    const formattedUsers = users.map((user) => ({
      _id: user._id,
      name: user.name,
      profileImages: user.profileImages,
      interests: user.interests,
      distance: Math.round(user.distance * 10) / 10, // Round to 1 decimal
      lastActiveAt: user.effectiveLastActive,
      activeStatus: formatActiveStatus(user.effectiveLastActive),
    }));

    console.log(
      `[NEARBY/OPEN] ${formattedUsers.length} users, hasMore=${hasMore}`,
    );

    res.status(200).json({
      users: formattedUsers,
      count: formattedUsers.length,
      hasMore,
    });
  } catch (error) {
    console.error("❌ [NEARBY/OPEN] Error fetching open users:", error);
    res.status(500).json({
      message: "Error fetching open users",
      error: error.message,
    });
  }
});

// PUT /users/:userId/open-visibility - Update user's visibility in Open tab
app.put("/users/:userId/open-visibility", async (req, res) => {
  try {
    const { userId } = req.params;
    const { showInOpenTab } = req.body;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    if (typeof showInOpenTab !== "boolean") {
      return res
        .status(400)
        .json({ message: "showInOpenTab must be a boolean" });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { showInOpenTab },
      { new: true },
    ).select("showInOpenTab");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: `Visibility ${showInOpenTab ? "enabled" : "disabled"}`,
      showInOpenTab: user.showInOpenTab,
    });
  } catch (error) {
    console.error("Error updating open visibility:", error);
    res.status(500).json({
      message: "Error updating visibility",
      error: error.message,
    });
  }
});

// GET /users/:userId/debug-location - Debug endpoint to check user's stored location
app.get("/users/:userId/debug-location", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    const user = await User.findById(userId).select("name location updatedAt");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const coords = user?.location?.coordinates;
    const lng = coords?.[0];
    const lat = coords?.[1];

    // Check if coords look like San Francisco (for debugging)
    const isSanFrancisco =
      lat &&
      lng &&
      Math.abs(lat - 37.7749) < 0.5 &&
      Math.abs(lng - -122.4194) < 0.5;

    res.status(200).json({
      userId,
      name: user.name,
      location: user.location,
      coordinates: { latitude: lat, longitude: lng },
      isSanFrancisco,
      lastUpdated: user.updatedAt,
      message: isSanFrancisco
        ? "⚠️ Location appears to be San Francisco - may need to update from real device"
        : "✅ Location looks valid",
    });
  } catch (error) {
    console.error("Error checking user location:", error);
    res
      .status(500)
      .json({ message: "Error checking location", error: error.message });
  }
});

// POST /events/:eventId/respond-suggestion - Accept or decline an activity suggestion
app.post("/events/:eventId/respond-suggestion", async (req, res) => {
  try {
    const { eventId } = req.params;
    const { userId, response } = req.body; // response: "accept" or "decline"

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID format" });
    }

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Valid user ID is required" });
    }

    if (!["accept", "decline"].includes(response)) {
      return res
        .status(400)
        .json({ message: "Response must be 'accept' or 'decline'" });
    }

    // Find the event
    const event = await Event.findById(eventId).populate(
      "hostId",
      "name profileImages pushToken",
    );

    if (!event) {
      return res.status(404).json({ message: "Activity not found" });
    }

    // Verify the event is a suggestion and this user is a recipient
    if (event.status !== "suggested") {
      return res
        .status(400)
        .json({ message: "This activity is not a suggestion" });
    }

    // Check if user is authorized (single suggestion or group invite)
    const isSingleRecipient = event.suggestedToUserId?.toString() === userId;
    const isGroupRecipient = event.suggestedToUserIds?.some(
      (id) => id.toString() === userId,
    );

    if (!isSingleRecipient && !isGroupRecipient) {
      return res
        .status(403)
        .json({
          message: "You are not authorized to respond to this suggestion",
        });
    }

    const isGroupInvite =
      event.suggestedToUserIds && event.suggestedToUserIds.length > 0;

    // Check if suggestion has expired
    if (event.expiresAt && new Date(event.expiresAt) < new Date()) {
      await Event.findByIdAndUpdate(eventId, { status: "cancelled" });
      return res.status(400).json({ message: "This suggestion has expired" });
    }

    if (response === "accept") {
      // Check if user already joined (prevent duplicate joins for group invites)
      const alreadyJoined = event.participants.some(
        (p) => p.userId?.toString() === userId,
      );
      if (alreadyJoined) {
        return res
          .status(400)
          .json({ message: "You have already accepted this activity" });
      }

      // Build the update
      const participantsToAdd = [];

      // For first acceptance, add the host as participant too
      const isFirstAcceptance = event.participants.length === 0;
      if (isFirstAcceptance) {
        participantsToAdd.push({
          userId: event.hostId._id,
          status: "going",
          joinedAt: new Date(),
        });
      }

      // Add the responding user
      participantsToAdd.push({
        userId: userId,
        status: "going",
        joinedAt: new Date(),
      });

      await Event.findByIdAndUpdate(eventId, {
        status: "upcoming",
        $push: {
          participants: { $each: participantsToAdd },
        },
      });

      // Notify the suggester that their suggestion was accepted
      const respondingUser =
        await User.findById(userId).select("name profileImages");

      await createNotificationWithCaps({
        userId: event.hostId._id,
        type: "suggestion_accepted",
        title: "Suggestion Accepted!",
        message: isGroupInvite
          ? `${respondingUser.name} joined your group activity: ${event.title}`
          : `${respondingUser.name} accepted your activity suggestion: ${event.title}`,
        eventId: event._id,
        eventName: event.title,
        actorId: userId,
        actorName: respondingUser.name,
        actorImage: respondingUser.profileImages?.[0],
      });

      res.status(200).json({
        message: "Suggestion accepted! Activity is now live.",
        event: await Event.findById(eventId).populate(
          "hostId",
          "name profileImages",
        ),
      });
    } else {
      // Decline: For group invites, just remove this user from the invite list
      // For single invites, cancel the event
      if (isGroupInvite) {
        // Remove user from suggestedToUserIds
        await Event.findByIdAndUpdate(eventId, {
          $pull: { suggestedToUserIds: new mongoose.Types.ObjectId(userId) },
        });

        // Check if all users have declined (no one left in the list)
        const updatedEvent = await Event.findById(eventId);
        if (
          updatedEvent.suggestedToUserIds.length === 0 &&
          updatedEvent.participants.length === 0
        ) {
          // No one accepted and everyone declined - cancel the event
          await Event.findByIdAndUpdate(eventId, { status: "cancelled" });
        }

        res.status(200).json({
          message: "Invitation declined",
        });
      } else {
        // Single invite - cancel the event
        await Event.findByIdAndUpdate(eventId, { status: "cancelled" });

        res.status(200).json({
          message: "Suggestion declined",
        });
      }
    }
  } catch (error) {
    console.error("Error responding to suggestion:", error);
    res.status(500).json({
      message: "Error responding to suggestion",
      error: error.message,
    });
  }
});

// POST /ratings - Submit a host rating
app.post("/ratings", async (req, res) => {
  try {
    const { eventId, raterId, hostId, stars, tags } = req.body;

    if (!eventId || !raterId || !hostId || !stars) {
      return res
        .status(400)
        .json({ message: "eventId, raterId, hostId, and stars are required" });
    }

    if (stars < 1 || stars > 5) {
      return res.status(400).json({ message: "Stars must be between 1 and 5" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    if (event.status !== "ended") {
      return res
        .status(400)
        .json({ message: "Can only rate after the event has ended" });
    }

    if (event.hostId.toString() !== hostId) {
      return res
        .status(400)
        .json({ message: "hostId does not match the event host" });
    }

    const wasParticipant = event.participants.some(
      (p) => p.userId.toString() === raterId,
    );
    if (!wasParticipant) {
      return res
        .status(403)
        .json({ message: "Only participants can rate the host" });
    }

    if (raterId === hostId) {
      return res.status(400).json({ message: "Cannot rate yourself" });
    }

    const rating = new Rating({
      eventId,
      raterId,
      hostId,
      stars,
      tags: tags || [],
    });

    await rating.save();

    // Positive rating: send "Glad you had fun" to guest (plan G12)
    if (stars >= 4) {
      try {
        const rater = await User.findById(raterId)
          .select("preferredLanguage")
          .lean();
        const lang = rater?.preferredLanguage;
        const str =
          lang && getStrings(lang).afterRating
            ? getStrings(lang).afterRating
            : getStrings("en").afterRating;
        await createNotificationWithCaps({
          userId: raterId,
          type: "after_rating",
          title: str.title,
          message: str.body,
          eventId,
          eventName: event.title,
        });
      } catch (notifErr) {
        console.error(
          "[Rating] after_rating notification failed:",
          notifErr?.message,
        );
      }
    }

    // Host 3rd rating milestone: send "Your reputation is building" (plan H7)
    const hostRatingCount = await Rating.countDocuments({ hostId });
    if (hostRatingCount === 3) {
      try {
        const hostUser = await User.findById(hostId)
          .select("preferredLanguage")
          .lean();
        const lang = hostUser?.preferredLanguage;
        const str =
          lang && getStrings(lang).hostThirdRating
            ? getStrings(lang).hostThirdRating
            : getStrings("en").hostThirdRating;
        const title = interpolate(str.title, {});
        const message = interpolate(str.body, { x: "3" });
        await createNotificationWithCaps({
          userId: hostId,
          type: "host_third_rating",
          title,
          message,
          eventId,
          eventName: event.title,
        });
      } catch (notifErr) {
        console.error(
          "[Rating] host_third_rating notification failed:",
          notifErr?.message,
        );
      }
    }

    res.status(201).json({ message: "Rating submitted", rating });
  } catch (error) {
    if (error.code === 11000) {
      return res
        .status(400)
        .json({ message: "You have already rated the host for this event" });
    }
    console.error("Error submitting rating:", error);
    res
      .status(500)
      .json({ message: "Error submitting rating", error: error.message });
  }
});

// GET /ratings/user/:userId - Get aggregate ratings for a user as host
app.get("/ratings/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const result = await Rating.aggregate([
      { $match: { hostId: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: null,
          averageRating: { $avg: "$stars" },
          totalRatings: { $sum: 1 },
          allTags: { $push: "$tags" },
        },
      },
    ]);

    if (!result.length) {
      return res
        .status(200)
        .json({ averageRating: 0, totalRatings: 0, tagCounts: {} });
    }

    const flatTags = result[0].allTags.flat();
    const tagCounts = {};
    for (const tag of flatTags) {
      tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    }

    res.status(200).json({
      averageRating: Math.round(result[0].averageRating * 10) / 10,
      totalRatings: result[0].totalRatings,
      tagCounts,
    });
  } catch (error) {
    console.error("Error fetching ratings:", error);
    res
      .status(500)
      .json({ message: "Error fetching ratings", error: error.message });
  }
});

// GET /ratings/check/:eventId/:userId - Check if user has rated for an event
app.get("/ratings/check/:eventId/:userId", async (req, res) => {
  try {
    const { eventId, userId } = req.params;

    if (
      !mongoose.Types.ObjectId.isValid(eventId) ||
      !mongoose.Types.ObjectId.isValid(userId)
    ) {
      return res.status(400).json({ message: "Invalid ID format" });
    }

    const existing = await Rating.findOne({ eventId, raterId: userId });
    res.status(200).json({ hasRated: !!existing });
  } catch (error) {
    console.error("Error checking rating:", error);
    res
      .status(500)
      .json({ message: "Error checking rating", error: error.message });
  }
});

// GET /users/:userId/stats - Get event attendance/hosting stats (from persisted User fields)
app.get("/users/:userId/stats", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const user = await User.findById(userId).select(
      "eventsHosted eventsAttended",
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      eventsAttended: user.eventsAttended ?? 0,
      eventsHosted: user.eventsHosted ?? 0,
    });
  } catch (error) {
    console.error("Error fetching user stats:", error);
    res
      .status(500)
      .json({ message: "Error fetching user stats", error: error.message });
  }
});

// POST /unblockUser - Remove a user from blocked list
app.post("/unblockUser", async (req, res) => {
  try {
    const { currentUserId, selectedUserId } = req.body;

    if (!currentUserId || !selectedUserId) {
      return res
        .status(400)
        .json({ message: "currentUserId and selectedUserId are required" });
    }

    await User.findByIdAndUpdate(selectedUserId, {
      $pull: { blockedBy: currentUserId },
    });

    res.status(200).json({ message: "User unblocked successfully" });
  } catch (error) {
    console.error("Error unblocking user:", error);
    res
      .status(500)
      .json({ message: "Error unblocking user", error: error.message });
  }
});

// GET /users/:userId/blocked - Get list of users blocked by this user
app.get("/users/:userId/blocked", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const blockedUsers = await User.find({
      blockedBy: userId,
    }).select("_id name profileImages");

    res.status(200).json({ blockedUsers });
  } catch (error) {
    console.error("Error fetching blocked users:", error);
    res
      .status(500)
      .json({ message: "Error fetching blocked users", error: error.message });
  }
});

// PUT /users/:userId/last-active - Update user's last active timestamp
app.put("/users/:userId/last-active", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    await User.findByIdAndUpdate(userId, { lastActiveAt: new Date() });

    res.status(200).json({ message: "Last active updated" });
  } catch (error) {
    console.error("Error updating last active:", error);
    res.status(500).json({
      message: "Error updating last active",
      error: error.message,
    });
  }
});
