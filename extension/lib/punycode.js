// Punycode decoding (RFC 3492). Decode only — nothing here ever encodes.
//
// Why this exists: `new URL()` hands back hostnames already punycode-encoded,
// so a Cyrillic lookalike arrives as "xn--aypal-8gg.com". The homoglyph folding
// in engine/urls.js maps Cyrillic р onto Latin p and would catch it instantly,
// but it never got the chance — by the time it ran, the characters it was built
// to recognise had been replaced by an ASCII envelope. Decoding first is what
// lets the folding that already exists do its job.
//
// Implemented rather than pulled in because there is no browser API that
// exposes it: `new URL()`, `location`, and an anchor element's `href` all
// return the encoded form, and Node's `punycode` module is deprecated and not
// available in a service worker.

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 0x7fffffff;
const DELIMITER = "-";
const PREFIX = "xn--";

// Maps a basic code point to its digit value. The reference implementation
// leans on unsigned wraparound for the out-of-range cases; JavaScript has no
// such thing, so every range is tested explicitly — "codePoint - 48 < 10" is
// true for every character *below* '0' here, which silently decodes garbage.
function digitValue(codePoint) {
  if (codePoint >= 0x30 && codePoint <= 0x39) return codePoint - 22; // 0-9 -> 26..35
  if (codePoint >= 0x41 && codePoint <= 0x5a) return codePoint - 65; // A-Z -> 0..25
  if (codePoint >= 0x61 && codePoint <= 0x7a) return codePoint - 97; // a-z -> 0..25
  return BASE; // invalid
}

function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);

  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) / 2) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/**
 * Decode one label's payload (everything after "xn--").
 * Returns null on anything malformed — a hostile hostname is not a reason to
 * throw, and the caller falls back to the encoded form.
 */
function decodeLabel(input) {
  const output = [];
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  // Everything before the last delimiter is literal ASCII. A delimiter at
  // position 0 means there is no basic-code-point section, not an empty one.
  const lastDelimiter = input.lastIndexOf(DELIMITER);
  const basicEnd = lastDelimiter > 0 ? lastDelimiter : 0;

  for (let j = 0; j < basicEnd; j += 1) {
    const codePoint = input.charCodeAt(j);
    if (codePoint >= 0x80) return null; // not a basic code point
    output.push(codePoint);
  }

  let index = basicEnd > 0 ? basicEnd + 1 : 0;

  while (index < input.length) {
    const oldI = i;

    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) return null;

      const digit = digitValue(input.charCodeAt(index));
      index += 1;
      if (digit >= BASE) return null;
      if (digit > Math.floor((MAX_INT - i) / w)) return null; // overflow

      i += digit * w;

      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;

      if (w > Math.floor(MAX_INT / (BASE - t))) return null; // overflow
      w *= BASE - t;
    }

    const out = output.length + 1;
    bias = adapt(i - oldI, out, oldI === 0);

    if (Math.floor(i / out) > MAX_INT - n) return null; // overflow
    n += Math.floor(i / out);
    i %= out;

    // Surrogates and out-of-range values are not decodable characters.
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;

    output.splice(i, 0, n);
    i += 1;
  }

  return output.length ? String.fromCodePoint(...output) : null;
}

/**
 * Decode every punycode label in a hostname. Labels that aren't punycode, and
 * labels that fail to decode, are passed through untouched.
 *
 * @param {string} host lowercase hostname, possibly punycode-encoded
 * @returns {string} the same hostname with any "xn--" labels decoded
 */
export function punycodeToUnicode(host) {
  if (!host || !host.includes(PREFIX)) return host;

  return host
    .split(".")
    .map((label) => {
      if (!label.startsWith(PREFIX)) return label;
      return decodeLabel(label.slice(PREFIX.length)) ?? label;
    })
    .join(".");
}
