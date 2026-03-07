const EXPO_BATCH_SIZE = 100;

const isValidExpoToken = (token) =>
  token &&
  typeof token === "string" &&
  (token.startsWith("ExponentPushToken[") || token.startsWith("ExpoPushToken[")) &&
  token.endsWith("]");

const sendNotification = async (expoPushToken, title, body) => {
  // Skip sending if no token or invalid format - never throw so callers (e.g. wave) don't fail
  const isValidToken = isValidExpoToken(expoPushToken);
  if (!isValidToken) {
    console.log(
      "[Push Notification] Skipping send: no valid Expo push token (missing or invalid format)"
    );
    return null;
  }

  const message = {
    to: expoPushToken,
    sound: "default",
    title,
    body,
    data: { someData: "goes here" },
  };

  try {
    console.log(
      `[Push Notification] Attempting to send to token: ${expoPushToken.substring(
        0,
        10
      )}...`
    );
    console.log(`[Push Notification] Title: "${title}"`);
    console.log(`[Push Notification] Body: "${body}"`);

    const response = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(message),
    });

    const responseData = await response.json();

    if (!response.ok) {
      console.error(`[Push Notification] Failed to send notification:`, {
        status: response.status,
        statusText: response.statusText,
        error: responseData,
      });
      throw new Error(
        `Failed to send notification: ${
          responseData.error || response.statusText
        }`
      );
    }

    console.log(
      `[Push Notification] Successfully sent to token: ${expoPushToken.substring(
        0,
        10
      )}...`
    );
    console.log(`[Push Notification] Response:`, responseData);

    return responseData;
  } catch (error) {
    console.error("[Push Notification] Error sending notification:", {
      error: error.message,
      token: expoPushToken.substring(0, 10) + "...",
      title,
      body,
    });
    throw error;
  }
};

/**
 * Send a single message to Expo (used when retrying after PUSH_TOO_MANY_EXPERIENCE_IDS).
 * Does not throw; returns false on failure.
 */
const sendOneToExpo = async (message) => {
  try {
    const body = {
      to: message.to,
      sound: "default",
      title: message.title,
      body: message.body,
      data: message.data || { someData: "goes here" },
    };
    const response = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) {
      console.error("[Push Notification] Single send failed:", message.to?.substring(0, 15), data);
      return false;
    }
    return true;
  } catch (err) {
    console.error("[Push Notification] Single send error:", err?.message || err);
    return false;
  }
};

/**
 * Send multiple push notifications to Expo in batches of EXPO_BATCH_SIZE (100).
 * If a batch fails with PUSH_TOO_MANY_EXPERIENCE_IDS (mixed Expo projects), retries
 * that chunk by sending each message in a separate request.
 * messages: Array<{ to: string, title: string, body: string }>
 * Invalid tokens are skipped. Does not throw so the worker can continue.
 */
const sendNotificationBatch = async (messages) => {
  if (!messages || messages.length === 0) return;
  const valid = messages.filter((m) => m && m.to && isValidExpoToken(m.to));
  for (let i = 0; i < valid.length; i += EXPO_BATCH_SIZE) {
    const chunk = valid.slice(i, i + EXPO_BATCH_SIZE).map((m) => ({
      to: m.to,
      sound: "default",
      title: m.title,
      body: m.body,
      data: m.data || { someData: "goes here" },
    }));
    try {
      const response = await fetch("https://exp.host/--/api/v2/push/send", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify(chunk),
      });
      const data = await response.json();
      const hasMixedProjects = Array.isArray(data?.errors) && data.errors.some(
        (e) => e && e.code === "PUSH_TOO_MANY_EXPERIENCE_IDS"
      );
      if (hasMixedProjects) {
        console.log("[Push Notification] Batch had mixed projects, retrying chunk as single messages:", chunk.length);
        let sent = 0;
        for (const msg of chunk) {
          const ok = await sendOneToExpo(msg);
          if (ok) sent++;
        }
        console.log(`[Push Notification] Retry sent ${sent}/${chunk.length} messages`);
      } else if (!response.ok) {
        console.error("[Push Notification] Batch send failed:", response.status, data);
      } else {
        console.log(`[Push Notification] Batch sent ${chunk.length} messages`);
      }
    } catch (err) {
      console.error("[Push Notification] Batch send error:", err?.message || err);
    }
  }
};

module.exports = { sendNotification, sendNotificationBatch, EXPO_BATCH_SIZE };
