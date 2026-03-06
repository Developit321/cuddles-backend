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
 * Send multiple push notifications to Expo in batches of EXPO_BATCH_SIZE (100).
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
      if (!response.ok) {
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
