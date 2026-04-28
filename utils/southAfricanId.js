/**
 * Validates a 13-digit South African national ID number (DHA checksum on first 12 digits).
 * @param {string} raw
 * @returns {boolean}
 */
function isValidSouthAfricanIdNumber(raw) {
  const id = String(raw || "").replace(/\D/g, "");
  if (id.length !== 13) return false;
  const digits = id.split("").map((c) => parseInt(c, 10));
  if (digits.some((d) => Number.isNaN(d))) return false;

  let sumOdd = 0;
  for (let i = 0; i < 12; i += 2) {
    sumOdd += digits[i];
  }

  let evenConcat = "";
  for (let i = 1; i < 12; i += 2) {
    evenConcat += String(digits[i]);
  }

  const doubled = String(parseInt(evenConcat, 10) * 2);
  let sumEvenDigits = 0;
  for (const ch of doubled) {
    sumEvenDigits += parseInt(ch, 10);
  }

  const total = sumOdd + sumEvenDigits;
  const check = (10 - (total % 10)) % 10;
  return check === digits[12];
}

module.exports = { isValidSouthAfricanIdNumber };
