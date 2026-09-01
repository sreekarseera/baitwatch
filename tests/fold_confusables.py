"""Python port of `foldConfusables(text, {substituteDigits: false})` from
extension/lib/text.js, for tests/test_parity.py's prediction comparison.

model.js vectorizes with `tokenize(normalize(text, {substituteDigits: false}))`
instead of raw `tokenize(text)` (commit 715649f) so the shipped model can see
through Unicode-confusable letters and styled/accented Latin. That makes
`classify()` diverge from `pipeline.predict_proba(raw_text)` on purpose — the
comparison has to fold the Python side the same way to stay apples-to-apples.
See docs/PROGRESS.md, "2026-09-01 (closing the cold audit)", finding 5.

The 273-entry confusable->ASCII-letter table is parsed straight out of the
generated extension/lib/confusables-data.js (its `PAIRS` string) rather than
hand-copied or re-derived from tools/build_confusables.py (which needs network
access to confusables.txt and is not run here). Parsing the shipped JS is the
only way to guarantee this table can't drift from the one the extension
actually uses.
"""

import pathlib
import re
import unicodedata

_REPO = pathlib.Path(__file__).resolve().parent.parent
_CONFUSABLES_JS = _REPO / "extension" / "lib" / "confusables-data.js"

# Combining marks stripped by both callers after folding — identical to
# COMBINING_MARKS in lib/text.js and MARKS in tools/build_confusables.py.
_COMBINING_MARKS = re.compile(r"[̀-ͯ]")


def _load_confusables_map():
    src = _CONFUSABLES_JS.read_text(encoding="utf-8")
    match = re.search(r'const PAIRS =\s*\n\s*"(.*)";', src)
    if not match:
        raise RuntimeError(f"could not find PAIRS string in {_CONFUSABLES_JS}")
    pairs = match.group(1)
    if len(pairs) % 2 != 0:
        raise RuntimeError(f"PAIRS string has odd length ({len(pairs)}) in {_CONFUSABLES_JS}")
    return {pairs[i]: pairs[i + 1] for i in range(0, len(pairs), 2)}


CONFUSABLES = _load_confusables_map()


def fold(text: str) -> str:
    """Match extension/lib/text.js's foldConfusables(text, {substituteDigits: false}):
    NFKD normalize, fold confusable letters, lowercase, strip combining marks.
    No digit substitution — the model's vocabulary was trained on unfolded digits.
    """
    folded = unicodedata.normalize("NFKD", text)
    folded = "".join(CONFUSABLES.get(ch, ch) for ch in folded)
    folded = folded.lower()
    return _COMBINING_MARKS.sub("", folded)
