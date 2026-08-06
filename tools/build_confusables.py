"""Fetch Unicode's confusables data and emit extension/lib/confusables-data.js.

The table's one job is to make a string comparable to a brand name: "раураl"
written in Cyrillic and "paypal" written in Latin have to arrive at the same
skeleton, or the lookalike check in engine/urls.js has nothing to compare. The
hand-picked table this replaces covered nine Cyrillic letters and ten Greek
ones, which meant an attacker only had to reach one letter further down the
alphabet to walk past it.

`confusables.txt` maps each character to the prototype of its confusability
class, and the classes are already transitively closed — Greek alpha maps
straight to `a`, not to some intermediate. So the selection below is a filter,
not a graph traversal.

WHAT IS INCLUDED, AND WHY THAT IS NOT "ALL OF IT"
------------------------------------------------
Only 273 of the file's 6565 mappings survive. Four rules do the cutting, and
each of them exists because the alternative breaks something real:

1. The target must be a single ASCII letter. Unicode's prototype for a class
   is frequently *not* ASCII — Greek epsilon's prototype is `ꞓ` (Latin c with
   bar), kappa's is `ĸ` (Latin kra), Cyrillic ve's is `ʙ` (small capital B).
   Unicode is saying those characters are confusable with each other and *not*
   with the plain ASCII letter, and it is right: folding ε to `e` is a guess.
   A mapping that lands anywhere other than ASCII is worse than useless to us,
   because comparing two non-ASCII skeletons tells us nothing about a brand.

2. The source must not be something NFKD already handles. Both callers run
   NFKD and strip combining marks before folding, so an entry for a character
   NFKD rewrites can never fire. This is where the size goes: 897 mappings,
   most of them the Mathematical Alphanumeric Symbols (𝐩𝐚𝐲𝐩𝐚𝐥, 𝓅𝒶𝓎𝓅𝒶𝓁,
   and eleven more styled Latin alphabets), are already folded for free.

3. The source's script must be on the allowlist below. This is the rule that
   matters most, and it is deliberately conservative — see the next section.

4. Expansions (one character to several) are dropped. They are ligatures and
   compatibility forms — `ĳ` to "ij", `℅` to "c/o" — which is NFKD's job, not
   ours, and none of them are the pixel-identical twins an attacker reaches
   for.

WHICH SCRIPTS, AND THE FAILURE THIS AVOIDS
------------------------------------------
This project has already shipped the bug that comes from treating a whole
script as suspicious: an earlier version flagged all punycode, which meant
every legitimate German, Russian, Chinese and Indian-language domain got a
warning. Folding every script in confusables.txt toward Latin would be the
same mistake wearing a different hat, so the allowlist covers three groups and
nothing else:

  * Latin beyond ASCII. Folding `ø`, `đ`, `ı`, `ƒ` onto their base letters is
    exactly what NFKD does for the accented ones; these are the letters it
    happens to leave alone.

  * Greek, Coptic, Cyrillic, Armenian — alphabets that share letterforms with
    Latin by common ancestry. Every real IDN homoglyph attack lives here, and
    the confusable pairs are genuine twins rather than resemblances.

  * Cherokee, Lisu, Deseret, Osage, Old Italic, Carian, Lycian, Elbasan —
    alphabets whose letters were *drawn from* Latin or Greek type. Sequoyah
    built the Cherokee syllabary out of letters he copied from a printed book;
    Fraser's Lisu alphabet is rotated Latin capitals; Deseret and Osage were
    designed from Latin. Their confusables are therefore exact, and none of
    them carries ordinary correspondence anyone sends today, so folding them
    cannot damage a message a real user receives.

Everything else is excluded on purpose, and the exclusions are worth naming:

  * Devanagari — this one is concrete, not precautionary. The Hindi and
    Hinglish rules in engine/heuristics.js match Devanagari literally
    (`ओटीपी`, `खात[ेा]`, `तुरंत`), and they read normalize()'d text. Folding
    Devanagari toward Latin would silently switch those rules off; the
    benchmark gates Devanagari scam detection at zero misses, so it would fail
    the build, but quietly breaking a whole language's rules is not something
    to leave to a gate.

  * Arabic, Hebrew, Thai, Ethiopic, Georgian, Myanmar, N'Ko, Tifinagh, the
    other Indic scripts, Han/Kana/Hangul, Canadian Aboriginal Syllabics —
    living scripts where Unicode's confusable is a shape coincidence rather
    than a shared letterform (Arabic-Indic `٥` for `o`). Folding them turns
    ordinary correspondence in those languages into Latin letter soup that the
    English rules then get to match, and buys no detection that the
    mixed-script signal in urls.js does not already carry.

  * Leetspeak digits (`0`→`o`, `1`→`l`, `@`→`a`) are NOT generated here even
    though Unicode agrees about two of them. They are a scammer convention,
    not a Unicode confusability class, so they stay hand-maintained in
    lib/text.js where they can be read and argued with. They are used here
    only to resolve a target that lands on a digit.

The output is a JS module rather than JSON so normalize() can stay
synchronous, for the same reason psl-data.js is.

Run:  python3 tools/build_confusables.py
"""

import pathlib
import re
import unicodedata
import urllib.request

SOURCE = "https://www.unicode.org/Public/security/latest/confusables.txt"
OUT = pathlib.Path(__file__).resolve().parent.parent / "extension/lib/confusables-data.js"

# Combining marks, stripped by both callers before folding. Kept in sync with
# the class in lib/text.js — it is why rule 2 above can discard so much.
MARKS = re.compile(r"[̀-ͯ]")

# Our leetspeak table, mirrored from lib/text.js. Used only to follow a target
# that lands on a digit through to the letter that digit already folds to, so
# the generated table never emits a mapping the caller would have to fold a
# second time. Digits with no leetspeak reading (2, 6, 8, 9) drop the mapping.
LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}

# The allowlist, as code point ranges. Ranges rather than script names because
# the local Python's Unicode version is usually older than the data file's, and
# a build whose output depends on which machine ran it is not a build.
INCLUDED = [
    # Latin beyond ASCII: the letters NFKD leaves alone (ø, đ, ı, ƒ, ʀ).
    ("Latin-1 Supplement, Latin Extended-A/B", 0x00C0, 0x024F),
    ("IPA Extensions", 0x0250, 0x02AF),
    ("Phonetic Extensions", 0x1D00, 0x1DBF),
    ("Latin Extended Additional", 0x1E00, 0x1EFF),
    ("Latin Extended-C", 0x2C60, 0x2C7F),
    ("Latin Extended-D", 0xA720, 0xA7FF),
    ("Latin Extended-E", 0xAB30, 0xAB6F),
    ("Latin Extended-F", 0x10780, 0x107BF),
    ("Latin Extended-G", 0x1DF00, 0x1DFFF),
    # Alphabets sharing letterforms with Latin by descent. This is where every
    # real homoglyph domain comes from.
    ("Greek and Coptic", 0x0370, 0x03FF),
    ("Greek Extended", 0x1F00, 0x1FFF),
    ("Coptic", 0x2C80, 0x2CFF),
    ("Cyrillic, Cyrillic Supplement", 0x0400, 0x052F),
    ("Cyrillic Extended-C", 0x1C80, 0x1C8F),
    ("Cyrillic Extended-A", 0x2DE0, 0x2DFF),
    ("Cyrillic Extended-B", 0xA640, 0xA69F),
    ("Cyrillic Extended-D", 0x1E030, 0x1E08F),
    ("Armenian", 0x0530, 0x058F),
    # Alphabets designed from Latin/Greek type, carrying no live correspondence.
    ("Cherokee", 0x13A0, 0x13FF),
    ("Cherokee Supplement", 0xAB70, 0xABBF),
    ("Lisu", 0xA4D0, 0xA4FF),
    ("Lisu Supplement", 0x11FB0, 0x11FBF),
    ("Deseret", 0x10400, 0x1044F),
    ("Osage", 0x104B0, 0x104FF),
    ("Old Italic", 0x10300, 0x1032F),
    ("Carian", 0x102A0, 0x102DF),
    ("Lycian", 0x10280, 0x1029F),
    ("Elbasan", 0x10500, 0x1052F),
]

# Asserted against the finished table. If a future revision of confusables.txt
# or a careless edit to INCLUDED ever lets one of these through, the build
# stops rather than shipping a table that garbles the language.
FORBIDDEN = [
    ("Devanagari", 0x0900, 0x097F),
    ("Bengali", 0x0980, 0x09FF),
    ("Gurmukhi", 0x0A00, 0x0A7F),
    ("Gujarati", 0x0A80, 0x0AFF),
    ("Oriya", 0x0B00, 0x0B7F),
    ("Tamil", 0x0B80, 0x0BFF),
    ("Telugu", 0x0C00, 0x0C7F),
    ("Kannada", 0x0C80, 0x0CFF),
    ("Malayalam", 0x0D00, 0x0D7F),
    ("Arabic", 0x0600, 0x06FF),
    ("Hebrew", 0x0590, 0x05FF),
    ("Thai", 0x0E00, 0x0E7F),
    ("Canadian Aboriginal Syllabics", 0x1400, 0x167F),
    ("CJK radicals, Kana, Bopomofo, Han", 0x2E80, 0x9FFF),
    ("Hangul syllables", 0xAC00, 0xD7FF),
    ("CJK compatibility ideographs", 0xF900, 0xFAFF),
]

HEADER = '''// GENERATED FILE — do not edit by hand. Run `python3 tools/build_confusables.py`.
//
// Source: Unicode Security Mechanisms (UTS #39), confusables.txt
// https://www.unicode.org/Public/security/latest/confusables.txt
// © Unicode, Inc. Used under the Unicode Terms of Use
// (https://www.unicode.org/terms_of_use.html). This is a filtered derivation,
// not the data file: {kept} of the source's {total} mappings survive.
//
// Every mapping folds a non-ASCII character onto exactly one ASCII letter, so
// a string can be compared against a brand name. Mappings that fold toward
// anything else were dropped, as were the scripts a fold would damage —
// Devanagari above all, because the Hindi rules in engine/heuristics.js match
// it literally. tools/build_confusables.py carries the full reasoning.
//
// Included:
{breakdown}
'''

BODY = '''
// Source and replacement, alternating. A `{{"а": "a", ...}}` object literal
// would spend eight bytes per entry on quotes, colons and commas; this spends
// two characters, and the pairs are rebuilt once at module load.
const PAIRS =
  "{pairs}";

// Array.from iterates by code point, not by UTF-16 unit — the Deseret, Osage
// and Carian sources are astral, and indexing PAIRS[i] would hand back half a
// surrogate pair.
const CODEPOINTS = Array.from(PAIRS);

export const CONFUSABLES = new Map();
for (let i = 0; i < CODEPOINTS.length; i += 2) {{
  CONFUSABLES.set(CODEPOINTS[i], CODEPOINTS[i + 1]);
}}

// One character class over every source, so folding is a single pass rather
// than a lookup per character. No escaping is needed: every source is
// non-ASCII by construction, so none of them can be `]`, `^`, `-` or `\\`.
export const CONFUSABLE_RE = new RegExp(
  `[${{[...CONFUSABLES.keys()].join("")}}]`,
  "gu"
);
'''


def fetch() -> str:
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        return response.read().decode("utf-8-sig")


def parse(text):
    """Yield (source, target) pairs, both as strings.

    Every line is `source ; target(s) ; category # comment`. The source is
    always one code point; the target may be several, which is why it is joined
    rather than indexed.
    """
    pairs = []
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(";")]
        if len(fields) < 3:
            continue
        source = chr(int(fields[0], 16))
        target = "".join(chr(int(cp, 16)) for cp in fields[1].split())
        pairs.append((source, target))
    return pairs


def block_of(char, ranges):
    code = ord(char)
    for name, start, end in ranges:
        if start <= code <= end:
            return name
    return None


def select(pairs):
    """Apply the four filters. Returns the table and a per-script breakdown."""
    table, breakdown = {}, {}

    for source, target in pairs:
        # Rule 4: expansions are NFKD's problem.
        if len(target) != 1:
            continue

        # Rule 1: the fold has to land on an ASCII letter. A digit target is
        # followed one step further through the leetspeak table the callers
        # apply anyway, so the result never needs folding twice.
        target = LEET.get(target, target)
        if not target.isascii() or not target.isalpha():
            continue

        # An ASCII source would mean folding Latin into something else, which
        # is the one thing this table must never do.
        if source.isascii():
            continue

        # Rule 2: both callers run NFKD and strip marks first, so a mapping for
        # a character NFKD rewrites is unreachable.
        if MARKS.sub("", unicodedata.normalize("NFKD", source)) != source:
            continue

        # Rule 3: allowlisted scripts only.
        name = block_of(source, INCLUDED)
        if name is None:
            continue

        # confusables.txt lists each source once, so a collision means the file
        # changed shape and the assumptions above need rereading.
        assert source not in table, f"duplicate source U+{ord(source):04X}"
        table[source] = target
        breakdown[name] = breakdown.get(name, 0) + 1

    return table, breakdown


def emit(table, breakdown, total) -> str:
    lines = [
        f"//   {count:4d}  {name}"
        for name, count in sorted(breakdown.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    header = HEADER.format(
        kept=len(table), total=total, breakdown="\n".join(lines)
    )
    pairs = "".join(source + target for source, target in sorted(table.items()))
    return header + BODY.format(pairs=pairs)


def check(table):
    """Refuse to write a table that would misbehave.

    These are the properties the rest of the engine relies on, stated once
    where a regeneration will trip over them.
    """
    if len(table) < 150:
        raise SystemExit(
            f"only {len(table)} mappings selected — the source looks truncated "
            f"or the filters are wrong, refusing to write"
        )

    for source, target in table.items():
        assert not source.isascii(), f"U+{ord(source):04X} folds an ASCII character"
        assert len(target) == 1 and target.isascii() and target.isalpha(), (
            f"U+{ord(source):04X} folds to {target!r}, which is not an ASCII letter"
        )
        forbidden = block_of(source, FORBIDDEN)
        assert forbidden is None, (
            f"U+{ord(source):04X} is {forbidden} — folding it would break text "
            f"the engine still has to read"
        )

    # The characters the hand-picked table covered, plus one from each of the
    # groups it did not. If a regeneration loses these, the lookalike check
    # loses the attacks it was written for.
    expected = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",  # Cyrillic
        "х": "x", "і": "i", "ѕ": "s", "ӏ": "l", "ј": "j",
        "α": "a", "ο": "o", "ρ": "p", "ι": "i", "ν": "v",  # Greek
        "σ": "o", "ϳ": "j",
        "ⲟ": "o", "ⲣ": "p",                                # Coptic
        "օ": "o", "ո": "n",                                # Armenian
        "ꮯ": "c", "ꓐ": "B", "𐐬": "o",                      # Cherokee, Lisu, Deseret
    }
    for source, target in expected.items():
        got = table.get(source)
        assert got == target, f"expected {source!r} -> {target!r}, got {got!r}"


def main():
    print(f"fetching {SOURCE}")
    pairs = parse(fetch())
    table, breakdown = select(pairs)

    check(table)
    OUT.write_text(emit(table, breakdown, len(pairs)), encoding="utf-8")

    size_kb = OUT.stat().st_size / 1024
    print(f"  kept {len(table)} of {len(pairs)} mappings")
    for name, count in sorted(breakdown.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"    {count:4d}  {name}")
    print(f"  wrote {OUT.relative_to(OUT.parent.parent.parent)} ({size_kb:.1f} KB)")
    print("  sanity checks passed")


if __name__ == "__main__":
    main()
