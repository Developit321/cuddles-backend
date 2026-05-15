const FREE_EVENT_MAX_CAPACITY = 10;
const PAID_EVENT_MAX_CAPACITY = Math.min(
  500,
  Math.max(1, Number(process.env.PAID_EVENT_MAX_CAPACITY) || 50)
);
const MIN_EVENT_CAPACITY = 1;

function getMaxCapacity(isPaid) {
  return isPaid ? PAID_EVENT_MAX_CAPACITY : FREE_EVENT_MAX_CAPACITY;
}

function validateCapacity({ capacity, isPaid }) {
  const max = getMaxCapacity(isPaid);
  const n = Number(capacity);
  if (!Number.isFinite(n) || n < MIN_EVENT_CAPACITY || n > max) {
    return {
      ok: false,
      message: `Capacity must be between ${MIN_EVENT_CAPACITY} and ${max}`,
    };
  }
  return { ok: true, value: Math.round(n) };
}

function getCapacityLimits() {
  return {
    min: MIN_EVENT_CAPACITY,
    freeMax: FREE_EVENT_MAX_CAPACITY,
    paidMax: PAID_EVENT_MAX_CAPACITY,
  };
}

module.exports = {
  FREE_EVENT_MAX_CAPACITY,
  PAID_EVENT_MAX_CAPACITY,
  MIN_EVENT_CAPACITY,
  getMaxCapacity,
  validateCapacity,
  getCapacityLimits,
};
