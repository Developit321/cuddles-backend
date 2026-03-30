/**
 * Bull queue for regional notification campaigns.
 * Isolated from nearby-notifications so existing workers are unaffected.
 */

let queue = null;

if (process.env.REDIS_URL) {
  try {
    const Queue = require("bull");
    queue = new Queue("regional-campaigns", process.env.REDIS_URL, {
      defaultJobOptions: { attempts: 2, backoff: { type: "exponential", delay: 2000 } },
    });
    queue.on("error", (err) => console.error("[Regional Queue] Redis error:", err?.message));
  } catch (err) {
    console.error("[Regional Queue] Failed to create queue:", err?.message);
  }
}

function getRegionalQueue() {
  return queue;
}

function enqueueRegionalCampaign(campaignId, runAt) {
  if (!queue) return null;
  const id = campaignId && campaignId.toString ? campaignId.toString() : campaignId;
  const options = {};
  if (runAt) {
    const ts = new Date(runAt).getTime();
    if (!Number.isNaN(ts) && ts > Date.now()) {
      options.delay = ts - Date.now();
    }
  }
  return queue
    .add({ type: "regional_campaign_run", campaignId: id }, options)
    .catch((err) => {
      console.error("[Regional Queue] enqueue regional campaign failed:", err?.message);
      return null;
    });
}

module.exports = { getRegionalQueue, enqueueRegionalCampaign };
