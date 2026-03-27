const mongoose = require("mongoose");
const RegionalCampaign = require("../models/RegionalCampaign");
const User = require("../models/User");
const Notification = require("../models/Notification");
const { sendNotification, sendNotificationBatch } = require("../notifications/pushNotifications");

const EVENTS_ONLY_QUERY = {
  $and: [
    { $or: [{ lookingFor: { $exists: false } }, { lookingFor: { $size: 0 } }] },
    { $or: [{ availability: { $exists: false } }, { availability: { $size: 0 } }] },
  ],
};

const BATCH_SIZE = 500;

function buildGeoQuery(campaign) {
  const matchConditions = [{ pushToken: { $exists: true, $ne: null } }];

  if (campaign.eventsOnly) {
    matchConditions.push(...EVENTS_ONLY_QUERY.$and);
  }
  if (campaign.audience?.gender) {
    matchConditions.push({ gender: campaign.audience.gender });
  }
  if (campaign.audience?.minLastActiveDays) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - campaign.audience.minLastActiveDays);
    matchConditions.push({ lastActiveAt: { $gte: cutoff } });
  }

  const pipeline = [];

  if (campaign.regionType === "country" && campaign.country) {
    pipeline.push({
      $match: {
        "location.country": campaign.country,
        $and: matchConditions,
      },
    });
  } else if (campaign.regionType === "radius" && campaign.center?.coordinates?.length === 2) {
    pipeline.push({
      $geoNear: {
        near: { type: "Point", coordinates: campaign.center.coordinates },
        distanceField: "distance",
        maxDistance: campaign.radiusM || 50000,
        spherical: true,
        query: { $and: matchConditions },
      },
    });
  } else if (campaign.regionType === "country_plus_radius") {
    if (campaign.country) {
      matchConditions.push({ "location.country": campaign.country });
    }
    pipeline.push({
      $geoNear: {
        near: { type: "Point", coordinates: campaign.center.coordinates },
        distanceField: "distance",
        maxDistance: campaign.radiusM || 50000,
        spherical: true,
        query: { $and: matchConditions },
      },
    });
  }

  pipeline.push({ $project: { _id: 1, pushToken: 1 } });
  return pipeline;
}

async function findTestUser(lookup) {
  if (!lookup) return null;
  const trimmed = lookup.trim();
  if (mongoose.Types.ObjectId.isValid(trimmed)) {
    return User.findById(trimmed).select("_id pushToken email name").lean();
  }
  if (trimmed.includes("@")) {
    return User.findOne({ email: trimmed.toLowerCase() }).select("_id pushToken email name").lean();
  }
  return User.findOne({ name: { $regex: new RegExp(`^${trimmed}$`, "i") } }).select("_id pushToken email name").lean();
}

async function executeCampaign(campaignId) {
  const campaign = await RegionalCampaign.findById(campaignId);
  if (!campaign) throw new Error(`Campaign ${campaignId} not found`);
  if (campaign.status !== "scheduled" && campaign.status !== "draft") {
    throw new Error(`Campaign ${campaignId} is ${campaign.status}, cannot execute`);
  }

  await RegionalCampaign.findByIdAndUpdate(campaignId, { status: "running", lastRunAt: new Date() });

  const metrics = {
    targetedCount: 0,
    eligibleCount: 0,
    sentCount: 0,
    skippedCapCount: 0,
    invalidTokenCount: 0,
    failedCount: 0,
  };

  try {
    let users;

    if (campaign.testUser) {
      const user = await findTestUser(campaign.testUser);
      if (!user) {
        throw new Error(`Test user "${campaign.testUser}" not found`);
      }
      users = [user];
      console.log(`[Campaign] Test mode — targeting single user: ${user.email || user.name || user._id}`);
    } else {
      const pipeline = buildGeoQuery(campaign);
      users = await User.aggregate(pipeline);
    }

    metrics.targetedCount = users.length;

    const validUsers = users.filter((u) => u.pushToken);
    metrics.invalidTokenCount = metrics.targetedCount - validUsers.length;
    metrics.eligibleCount = validUsers.length;

    if (campaign.testUser && validUsers.length > 0) {
      const u = validUsers[0];
      try {
        await sendNotification(u.pushToken, campaign.title, campaign.message);
        metrics.sentCount = 1;
      } catch (err) {
        console.error("[Campaign] Test send error:", err?.message || err);
        metrics.failedCount = 1;
      }
    } else {
      for (let i = 0; i < validUsers.length; i += BATCH_SIZE) {
        const batch = validUsers.slice(i, i + BATCH_SIZE);
        const messages = batch.map((u) => ({
          to: u.pushToken,
          title: campaign.title,
          body: campaign.message,
        }));

        try {
          await sendNotificationBatch(messages);
          metrics.sentCount += messages.length;
        } catch (err) {
          console.error("[Campaign] Batch send error:", err?.message || err);
          metrics.failedCount += messages.length;
        }
      }
    }

    const notificationDocs = validUsers.map((u) => ({
      userId: u._id,
      type: "regional_campaign",
      category: "discovery",
      title: campaign.title,
      message: campaign.message,
    }));
    if (notificationDocs.length > 0) {
      await Notification.insertMany(notificationDocs, { ordered: false }).catch(() => {});
    }

    await RegionalCampaign.findByIdAndUpdate(campaignId, {
      status: "completed",
      metrics,
    });

    console.log(
      `[Campaign] ${campaign.name} completed: ${metrics.sentCount} sent, ${metrics.failedCount} failed out of ${metrics.targetedCount} targeted`
    );
  } catch (err) {
    console.error(`[Campaign] ${campaign.name} failed:`, err?.message || err);
    await RegionalCampaign.findByIdAndUpdate(campaignId, {
      status: "failed",
      metrics,
    });
  }

  return metrics;
}

module.exports = { executeCampaign, buildGeoQuery };
