const sendNotification = async (expoPushToken, title, body) => {
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

module.exports = { sendNotification };
