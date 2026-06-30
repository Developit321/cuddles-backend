/**
 * Add a user to an event by EVENT TITLE + USER EMAIL.
 *
 * If the event is full, capacity is automatically increased to fit the user
 * (unless --no-grow is passed) and the user is added to the count.
 *
 * Usage:
 *   node scripts/addUserToEvent.js "Event Title" user@email.com
 *   node scripts/addUserToEvent.js "Event Title" user@email.com --status going
 *   node scripts/addUserToEvent.js "Event Title" user@email.com --no-grow
 *
 * Flags:
 *   --status <interested|going|checked_in>  Participant status to add (default: going)
 *   --no-grow                               Do NOT auto-increase capacity when full
 *
 * Notes:
 *   - Title match is case-insensitive and trimmed. If multiple events share the
 *     title, the matches are listed and you must disambiguate (use the API/DB id).
 *   - Adding with status "going" makes the user count toward occupied seats.
 */

const mongoose = require("mongoose");
const Event = require("../models/Event");
const User = require("../models/User");
const { countOccupiedSeats, computeNextEventStatus } = require("../services/eventSeatHold");
const { getMaxCapacity } = require("../utils/eventCapacity");

const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://cuddles:LNum9ZwrrcNDyl5c@cluster0.bdtblda.mongodb.net/";

const VALID_STATUSES = ["interested", "going", "checked_in"];

function parseArgs(argv) {
  const positional = [];
  let status = "going";
  let grow = true;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--status") {
      status = argv[++i];
    } else if (arg === "--no-grow") {
      grow = false;
    } else if (arg.startsWith("--status=")) {
      status = arg.split("=")[1];
    } else {
      positional.push(arg);
    }
  }

  return {
    title: positional[0],
    email: positional[1],
    status,
    grow,
  };
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function main() {
  const { title, email, status, grow } = parseArgs(process.argv.slice(2));

  if (!title || !email) {
    console.error(
      'Usage: node scripts/addUserToEvent.js "<Event Title>" <user@email.com> [--status going] [--no-grow]'
    );
    process.exit(1);
  }

  if (!VALID_STATUSES.includes(status)) {
    console.error(
      `Invalid --status "${status}". Must be one of: ${VALID_STATUSES.join(", ")}`
    );
    process.exit(1);
  }

  await mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    // 1. Find the user by email (case-insensitive, trimmed)
    const normalizedEmail = email.trim();
    const user = await User.findOne({
      email: { $regex: `^${escapeRegex(normalizedEmail)}$`, $options: "i" },
    }).select("_id name email");

    if (!user) {
      console.error(`No user found with email: ${normalizedEmail}`);
      process.exit(1);
    }

    // 2. Find the event by title (case-insensitive exact match, trimmed)
    const normalizedTitle = title.trim();
    const events = await Event.find({
      title: { $regex: `^${escapeRegex(normalizedTitle)}$`, $options: "i" },
    });

    if (events.length === 0) {
      console.error(`No event found with title: "${normalizedTitle}"`);
      process.exit(1);
    }

    if (events.length > 1) {
      console.error(
        `Multiple events (${events.length}) match title "${normalizedTitle}". Please disambiguate:`
      );
      events.forEach((e) => {
        console.error(
          `  - ${e._id}  | starts ${new Date(e.startTime).toISOString()} | status=${e.status} | cap=${e.capacity}`
        );
      });
      process.exit(1);
    }

    const event = events[0];

    // 3. Already a participant? (idempotent)
    const uid = user._id.toString();
    const existing = event.participants.find((p) => {
      const raw = p.userId?._id || p.userId;
      return raw && raw.toString() === uid;
    });

    if (existing) {
      if (existing.status !== status) {
        console.log(
          `${user.email} is already a participant (status="${existing.status}"). Updating to "${status}".`
        );
        existing.status = status;
        event.status = computeNextEventStatus(event);
        await event.save();
      } else {
        console.log(
          `${user.email} is already a participant of "${event.title}" with status "${status}". Nothing to do.`
        );
      }
      return;
    }

    // 4. Capacity check — grow if full
    const occupied = countOccupiedSeats(event);
    const capacity = event.capacity != null ? event.capacity : 6;
    const seatTaking = status === "going" || status === "checked_in" || event.isPaid;

    if (seatTaking && occupied >= capacity) {
      if (!grow) {
        console.error(
          `Event "${event.title}" is full (${occupied}/${capacity}) and --no-grow was set. Not adding.`
        );
        process.exit(1);
      }
      const newCapacity = occupied + 1;
      const maxCapacity = getMaxCapacity(event.isPaid);
      if (newCapacity > maxCapacity) {
        console.warn(
          `Warning: new capacity ${newCapacity} exceeds the normal max (${maxCapacity}) for this event type. Proceeding as an admin override.`
        );
      }
      console.log(
        `Event "${event.title}" is full (${occupied}/${capacity}). Increasing capacity to ${newCapacity}.`
      );
      event.capacity = newCapacity;
    }

    // 5. Add the participant
    event.participants.push({
      userId: user._id,
      status,
      joinedAt: new Date(),
    });
    event.status = computeNextEventStatus(event);

    await event.save();

    const occupiedAfter = countOccupiedSeats(event);
    console.log(
      `Added ${user.name || user.email} (${user.email}) to "${event.title}" as "${status}".`
    );
    console.log(
      `Occupied seats: ${occupiedAfter}/${event.capacity} | event status: ${event.status}`
    );
  } finally {
    await mongoose.disconnect().catch(() => {});
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
