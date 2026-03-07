/**
 * Bull queue for nearby notifications (event_nearby, event_nearby_60).
 * Only created when REDIS_URL is set; otherwise enqueue is a no-op.
 */

let queue = null;

if (process.env.REDIS_URL) {
  try {
    const Queue = require("bull");
    queue = new Queue("nearby-notifications", process.env.REDIS_URL, {
      defaultJobOptions: { attempts: 2, backoff: { type: "exponential", delay: 2000 } },
    });
    queue.on("error", (err) => console.error("[Nearby Queue] Redis error:", err?.message));
  } catch (err) {
    console.error("[Nearby Queue] Failed to create queue:", err?.message);
  }
}

function getQueue() {
  return queue;
}

function enqueueNearbyEvent(eventId) {
  if (!queue) return;
  const id = eventId && eventId.toString ? eventId.toString() : eventId;
  queue.add({ type: "event_nearby", eventId: id }).catch((err) => console.error("[Nearby Queue] enqueue event_nearby failed:", err?.message));
}

function enqueueNearby60Fill(eventId) {
  if (!queue) return;
  const id = eventId && eventId.toString ? eventId.toString() : eventId;
  queue.add({ type: "event_nearby_60", eventId: id }).catch((err) => console.error("[Nearby Queue] enqueue event_nearby_60 failed:", err?.message));
}

function enqueueCapetownWeekend() {
  if (!queue) return;
  queue.add({ type: "capetown_weekend" }).catch((err) => console.error("[Nearby Queue] enqueue capetown_weekend failed:", err?.message));
}

module.exports = { getQueue, enqueueNearbyEvent, enqueueNearby60Fill, enqueueCapetownWeekend };
