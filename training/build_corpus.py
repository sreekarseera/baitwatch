"""Build dataset.csv from the SpamAssassin public corpus plus the curated rows.

Why this exists: the hand-written dataset is 281 rows and partly
template-generated, and five-fold cross-validation on it ran at 93% +/- 18%.
That variance is the problem — with ~56 rows per fold, the score mostly
reports which examples landed in which fold. Real mail is the fix.

The corpus (https://spamassassin.apache.org/old/publiccorpus/) is offered by
the SpamAssassin project "as a service to spam filter developers"; its messages
"were posted to public fora, were sent to me in the knowledge that they may be
made public, were sent by me, or originated as newsletters from public news web
sites". Training a spam filter is squarely the intended use.

Two things it fixes beyond raw volume:

  * hard_ham is mail that *looks* like spam — newsletters, marketing, offers
    from real senders. It is the single most useful thing in the corpus for a
    tool whose failure mode is crying wolf.

  * the curated ham averages 61 characters and the curated scams 100, so
    length alone carried real signal. Nothing in deployment looks like that.
    Real mail on both sides removes the confound.

The curated rows are kept, not replaced. They carry the India-specific scams
(UPI collect-requests, digital-arrest threats, KYC expiry) that a 2002 American
corpus has never heard of, and those are the ones this project exists for.

Messages are redacted before they are written: headers are dropped entirely,
and any address surviving in a body is replaced. The output goes into a public
repository, and 2002 mail has real people in it.

    python3 build_corpus.py            # uses ./corpus-cache, downloads if absent
    python3 build_corpus.py --cache DIR
"""

import argparse
import csv
import email
import email.policy
import hashlib
import html
import pathlib
import random
import re
import sys
import tarfile
import urllib.request

BASE = "https://spamassassin.apache.org/old/publiccorpus/"
ARCHIVES = {
    "easy_ham": "20030228_easy_ham.tar.bz2",
    "hard_ham": "20030228_hard_ham.tar.bz2",
    "spam": "20030228_spam.tar.bz2",
    "spam_2": "20050311_spam_2.tar.bz2",
}

HERE = pathlib.Path(__file__).resolve().parent
CURATED = HERE / "curated.csv"
OUT = HERE / "dataset.csv"

# How many to take from each folder. easy_ham is capped rather than taken whole:
# it is 2500 messages of 2002 mailing-list traffic, and past a point more of it
# only teaches the model what Linux users argued about. hard_ham is taken whole
# because every row of it is a false positive waiting to happen.
QUOTAS = {"easy_ham": 1250, "hard_ham": 251, "spam": 501, "spam_2": 1000}

# Long enough to hold the pretext, short enough that one forwarded thread can't
# outweigh fifty ordinary messages. Deployment truncates too.
MAX_CHARS = 1200
MIN_CHARS = 40

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TAG_RE = re.compile(r"<[^>]+>")
QUOTED_RE = re.compile(r"^\s*>.*$", re.MULTILINE)
SPACE_RE = re.compile(r"[ \t\r\f\v]+")
BLANKS_RE = re.compile(r"\n{3,}")


def fetch(cache: pathlib.Path) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    for name, archive in ARCHIVES.items():
        if (cache / name).is_dir():
            continue
        target = cache / archive
        if not target.exists():
            print(f"  downloading {archive}")
            urllib.request.urlretrieve(BASE + archive, target)
        print(f"  extracting {archive}")
        with tarfile.open(target) as tar:
            # filter="data" refuses absolute paths and traversal. This is
            # third-party input; there is no reason to extract it trustingly.
            try:
                tar.extractall(cache, filter="data")
            except TypeError:  # Python < 3.12
                tar.extractall(cache)


def body_of(raw: bytes) -> str:
    """Subject plus plain-text body, headers otherwise discarded.

    Headers are where the addresses, routing, and 2002 hostnames live. None of
    it is available to the extension at scan time either — the adapters hand
    over rendered message text — so training on it would teach the model
    signals it will never see again.
    """
    message = email.message_from_bytes(raw, policy=email.policy.default)

    subject = str(message.get("subject") or "")

    text = ""
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    text = part.get_content()
                    break
                except (LookupError, ValueError):
                    continue
        if not text:
            for part in message.walk():
                if part.get_content_type() == "text/html":
                    try:
                        text = TAG_RE.sub(" ", part.get_content())
                        break
                    except (LookupError, ValueError):
                        continue
    else:
        try:
            text = message.get_content()
        except (LookupError, ValueError):
            text = raw.decode("utf-8", "replace")
        if message.get_content_type() == "text/html":
            text = TAG_RE.sub(" ", text)

    return f"{subject}\n{text}"


def clean(text: str) -> str:
    # After tag-stripping the entities are still encoded, and "&#x2019;" is not
    # a word the extension will ever meet. Unescaping twice is deliberate: a
    # fair amount of this corpus is double-encoded.
    text = html.unescape(html.unescape(text))
    text = QUOTED_RE.sub("", text)  # quoted replies are the other person's words
    text = EMAIL_RE.sub("someone@example.com", text)
    text = SPACE_RE.sub(" ", text)
    text = BLANKS_RE.sub("\n\n", text)
    return text.strip()[:MAX_CHARS]


def harvest(cache: pathlib.Path, folder: str, quota: int, rng: random.Random):
    paths = sorted(p for p in (cache / folder).iterdir() if p.is_file() and "cmds" not in p.name)
    rng.shuffle(paths)

    rows = []
    for path in paths:
        if len(rows) >= quota:
            break
        try:
            text = clean(body_of(path.read_bytes()))
        except Exception:
            continue  # a corpus of real mail contains genuinely broken mail
        if len(text) >= MIN_CHARS:
            rows.append(text)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", default=str(HERE / "corpus-cache"))
    args = parser.parse_args()

    cache = pathlib.Path(args.cache)
    print(f"corpus cache: {cache}")
    fetch(cache)

    if not CURATED.exists():
        sys.exit(f"missing {CURATED} — the curated rows are not regenerable, restore them first")

    rng = random.Random(20260805)  # fixed: the dataset must rebuild identically
    rows = []

    with CURATED.open(encoding="utf-8") as f:
        curated = [(r["text"], int(r["label"])) for r in csv.DictReader(f)]
    rows.extend(curated)
    print(f"  curated:  {len(curated)}")

    for folder, quota in QUOTAS.items():
        label = 0 if "ham" in folder else 1
        harvested = harvest(cache, folder, quota, rng)
        rows.extend((text, label) for text in harvested)
        print(f"  {folder:9} {len(harvested)} (label {label})")

    # Exact duplicates are common in the corpus and inflate cross-validation:
    # the same message landing in two folds is a free correct answer.
    seen = set()
    unique = []
    for text, label in rows:
        digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unique.append((text, label))

    rng.shuffle(unique)

    with OUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(unique)

    scams = sum(label for _, label in unique)
    print(f"\nwrote {OUT.relative_to(HERE.parent)}")
    print(f"  {len(unique)} rows ({len(rows) - len(unique)} duplicates dropped)")
    print(f"  {scams} scam / {len(unique) - scams} legitimate")


if __name__ == "__main__":
    main()
