# Notifications

This folder holds **caps**, **copy**, and **push sending**. Event notification **triggers** (when to send) live in **api/index.js**.

| Concern | Location |
|--------|----------|
| Cap enforcement, category mapping | `api/notifications/notificationCaps.js` |
| Copy (titles/bodies, i18n) | `api/notifications/notificationStrings.js` |
| Sending push (Expo) | `api/notifications/pushNotifications.js` |
| **When** to send (crons, event create/join, suggestions, rating reminders, etc.) | **api/index.js** |

When adding or changing an event notification type:

1. Add the type to the Notification model enum and set its category in `notificationCaps.js` (`getCategoryForType`).
2. Add or update copy in `notificationStrings.js` if needed.
3. Add or update the **trigger** in `api/index.js` (e.g. in a cron, or in the event/suggestion/join handlers) and use `createNotificationWithCaps` so caps are applied.

See **api/notificationplan.md** for limits and copy.
