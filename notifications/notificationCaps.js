/**
 * Notification cap enforcement for Invitable — limits FOMO, re-engagement, and
 * global non-transactional notifications per user so we don't annoy users.
 * See api/notificationplan.md for limits.
 *
 * Note: Event notification logic is split across two places:
 * - This folder (api/notifications/): caps, strings, push send.
 * - api/index.js: where notifications are triggered (crons, event creation,
 *   joins, suggestions, rating reminders, etc.). When adding or changing
 *   event notification types, update both the Notification model, getCategoryForType
 *   here, and the trigger code in index.js.
 */

const Notification = require("../models/Notification");

const GLOBAL_NON_TRANSACTIONAL_CAP_PER_DAY = 3;
const FOMO_CAP_PER_DAY = 3;
const RE_ENGAGEMENT_CAP_PER_WEEK = 1;

/** Categories that count toward the global non-transactional daily cap. Discovery (event_nearby) is unlimited for now. */
const NON_TRANSACTIONAL_CATEGORIES = ["fomo", "re_engagement"];

/**
 * Start of today in UTC (midnight UTC). Use for "today" window in cap checks.
 */
function startOfTodayUTC() {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return d;
}

/**
 * Start of 7 days ago in UTC (for re-engagement weekly window).
 */
function startOfWeekAgoUTC() {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - 7);
  d.setUTCHours(0, 0, 0, 0);
  return d;
}

/**
 * Count non-transactional notifications sent to user today.
 * Only fomo + re_engagement count; discovery (event_nearby) is unlimited per plan.
 */
async function getNonTransactionalCountToday(userId) {
  const start = startOfTodayUTC();
  const count = await Notification.countDocuments({
    userId,
    category: { $in: NON_TRANSACTIONAL_CATEGORIES },
    createdAt: { $gte: start },
  });
  return count;
}

/**
 * Count FOMO notifications sent to user today (max FOMO_CAP_PER_DAY per day).
 */
async function getFomoCountToday(userId) {
  const start = startOfTodayUTC();
  const count = await Notification.countDocuments({
    userId,
    category: "fomo",
    createdAt: { $gte: start },
  });
  return count;
}

/**
 * Count re-engagement notifications sent to user in the last 7 days (max 1 per week).
 */
async function getReEngagementCountThisWeek(userId) {
  const start = startOfWeekAgoUTC();
  const count = await Notification.countDocuments({
    userId,
    category: "re_engagement",
    createdAt: { $gte: start },
  });
  return count;
}

/**
 * Whether the user received any transactional notification today.
 * Plan: "If a user already received a transactional notification that day, skip re-engagement and discovery nudges entirely."
 */
async function hadTransactionalToday(userId) {
  const start = startOfTodayUTC();
  const count = await Notification.countDocuments({
    userId,
    category: "transactional",
    createdAt: { $gte: start },
  });
  return count > 0;
}

/**
 * Whether we should send a notification of the given category to the user.
 * Transactional: always allowed. FOMO/re_engagement: subject to per-type and global caps.
 * Re-engagement only: skipped if user already got a transactional notification today (discovery is not skipped).
 *
 * @param {string|ObjectId} userId
 * @param {string} category - One of: transactional, discovery, fomo, re_engagement, post_experience
 * @returns {Promise<{ allowed: boolean, reason?: string }>}
 */
async function shouldSendNotification(userId, category) {
  if (!category || category === "transactional" || category === "post_experience") {
    return { allowed: true };
  }

  if (category === "discovery") {
    // Discovery (e.g. new table nearby) is not skipped when user had transactional today — discovery stays high priority.
    return { allowed: true };
  }

  if (category === "fomo") {
    const countToday = await getFomoCountToday(userId);
    if (countToday >= FOMO_CAP_PER_DAY) {
      return { allowed: false, reason: `FOMO cap reached (${FOMO_CAP_PER_DAY}/day)` };
    }
    const nonTxToday = await getNonTransactionalCountToday(userId);
    if (nonTxToday >= GLOBAL_NON_TRANSACTIONAL_CAP_PER_DAY) {
      return { allowed: false, reason: `Global non-transactional cap reached (${GLOBAL_NON_TRANSACTIONAL_CAP_PER_DAY}/day)` };
    }
    return { allowed: true };
  }

  if (category === "re_engagement") {
    const hadTx = await hadTransactionalToday(userId);
    if (hadTx) {
      return { allowed: false, reason: "User already received a transactional notification today; skip re-engagement" };
    }
    const countThisWeek = await getReEngagementCountThisWeek(userId);
    if (countThisWeek >= RE_ENGAGEMENT_CAP_PER_WEEK) {
      return { allowed: false, reason: `Re-engagement cap reached (${RE_ENGAGEMENT_CAP_PER_WEEK}/week)` };
    }
    const nonTxToday = await getNonTransactionalCountToday(userId);
    if (nonTxToday >= GLOBAL_NON_TRANSACTIONAL_CAP_PER_DAY) {
      return { allowed: false, reason: `Global non-transactional cap reached (${GLOBAL_NON_TRANSACTIONAL_CAP_PER_DAY}/day)` };
    }
    return { allowed: true };
  }

  return { allowed: true };
}

/**
 * Maps notification type to category for cap enforcement.
 * Used when creating notifications so we can store category and enforce caps.
 */
function getCategoryForType(type) {
  const transactional = [
    "event_joined",
    "event_reminder",
    "event_cancelled",
    "event_updated",
    "event_checkin",
    "event_removed",
    "table_60_full",
    "rate_host",
    "suggestion_accepted",
    "suggestion_declined",
    "boost_activated",
    "boost_warning",
    "boost_expired",
    "boost_credits_reset",
    "profile_like",
    "super_wave",
    "event_join_request",
    "event_join_request_rejected",
  ];
  if (transactional.includes(type)) return "transactional";
  if (type === "activity_suggestion") return "transactional"; // direct invite
  if (type === "event_nearby") return "discovery";
  if (type === "suggestion_expired") return "transactional";
  if (type === "after_rating" || type === "host_third_rating") return "post_experience";
  if (type === "table_filling_fast") return "fomo";
  if (type === "capetown_weekend") return "re_engagement";
  return "transactional";
}

module.exports = {
  getNonTransactionalCountToday,
  getFomoCountToday,
  getReEngagementCountThisWeek,
  shouldSendNotification,
  getCategoryForType,
  GLOBAL_NON_TRANSACTIONAL_CAP_PER_DAY,
  FOMO_CAP_PER_DAY,
  RE_ENGAGEMENT_CAP_PER_WEEK,
};
