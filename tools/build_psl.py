"""Fetch Mozilla's Public Suffix List and emit extension/engine/psl-data.js.

The list decides where a hostname stops being controlled by a registrar and
starts being controlled by whoever registered it. Without it, `evil.github.io`
and `legit.github.io` collapse to the same registrable domain, which is
exactly the confusion phishing pages hosted on free platforms rely on.

Both sections are kept. The ICANN section covers real public suffixes
(`co.uk`); the PRIVATE section covers hosting platforms (`github.io`,
`vercel.app`, `pages.dev`) — and for our purposes the private section is the
more valuable of the two, because that is where free phishing hosting lives.

The output is a JS module rather than JSON so `registrableDomain()` can stay
synchronous. An async fetch would ripple through every caller in the engine
for no benefit.

Run:  python3 tools/build_psl.py
"""

import pathlib
import urllib.request

SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"
OUT = pathlib.Path(__file__).resolve().parent.parent / "extension/engine/psl-data.js"

HEADER = '''// GENERATED FILE — do not edit by hand. Run `python3 tools/build_psl.py`.
//
// Source: Mozilla Public Suffix List (https://publicsuffix.org/)
// Licensed under the Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/).
// The list is redistributed here unmodified apart from stripping comments and
// blank lines; MPL-2.0 applies to this data file only and does not affect the
// license of the rest of BaitWatch.
//
// Rules: {rules} exact, {wildcards} wildcard, {exceptions} exception.

'''


def fetch() -> str:
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        return response.read().decode("utf-8")


def parse(text):
    """Split the list into exact rules, wildcards, and exceptions.

    A `*.foo` rule means any single label under `foo` is itself a public
    suffix. A `!bar.foo` rule is an exception carving `bar.foo` back out.
    Storing them separately keeps lookup to a few set probes per hostname
    instead of a scan over 16k entries.
    """
    rules, wildcards, exceptions = set(), set(), set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(line[1:])
        elif line.startswith("*."):
            wildcards.add(line[2:])
        else:
            rules.add(line)

    return rules, wildcards, exceptions


def emit(rules, wildcards, exceptions) -> str:
    """Write the sets as newline-joined strings.

    A JS array literal would spend two bytes per entry on quotes and commas —
    about 60 KB across the full list. Splitting one string at module load
    costs a few milliseconds once and is dramatically smaller on disk.
    """
    def block(name, values):
        joined = "\\n".join(sorted(values))
        return f'export const {name} = new Set("{joined}".split("\\n"));\n'

    body = HEADER.format(
        rules=len(rules), wildcards=len(wildcards), exceptions=len(exceptions)
    )
    body += block("PSL_RULES", rules)
    body += "\n"
    body += block("PSL_WILDCARDS", wildcards)
    body += "\n"
    body += block("PSL_EXCEPTIONS", exceptions)
    return body


def main():
    print(f"fetching {SOURCE}")
    rules, wildcards, exceptions = parse(fetch())

    if len(rules) < 5000:
        raise SystemExit(
            f"only {len(rules)} rules parsed — the list looks truncated, refusing to write"
        )

    OUT.write_text(emit(rules, wildcards, exceptions), encoding="utf-8")

    size_kb = OUT.stat().st_size / 1024
    print(f"  {len(rules)} exact, {len(wildcards)} wildcard, {len(exceptions)} exception")
    print(f"  wrote {OUT.relative_to(OUT.parent.parent.parent)} ({size_kb:.0f} KB)")

    for check in ("github.io", "vercel.app", "co.uk", "com"):
        assert check in rules, f"expected {check} in the list"
    print("  sanity checks passed")


if __name__ == "__main__":
    main()
