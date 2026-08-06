"""Build the Chrome Web Store upload zip from extension/.

The store wants a zip whose root *is* the extension — `manifest.json` at the
top level, not inside a folder. Zipping the `extension/` directory from the
Finder produces the wrong shape and the dashboard rejects it with an unhelpful
error, so this exists mostly to stop that happening at the worst moment.

It also refuses to build rather than shipping something a reviewer would bounce.
The checks below are the ones that have a specific, known consequence: a
description over 132 characters is rejected outright, a missing icon breaks the
listing, `console.log` and source maps in shipped code read as an unfinished
build, and a file inside the package that nothing references is a permission
question waiting to be asked. Each one is cheap to check here and expensive to
discover after an upload.

Nothing outside `extension/` goes in. The training corpus, the tests, the model
`.joblib` and the docs stay in the repository where they are useful and out of
the package where they are 30 MB of attack surface.

Run:  python3 tools/package.py
"""

import json
import pathlib
import re
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "extension"
DIST = ROOT / "dist"

# Store limits, from the developer dashboard.
MAX_DESCRIPTION = 132
REQUIRED_ICONS = ("16", "48", "128")

# Editor and OS droppings, plus build output that should never reach a package
# this project does not build. Matched against the path relative to extension/.
EXCLUDE = re.compile(
    r"(^|/)\.|(\.map|\.orig|\.rej|\.bak|~)$|(^|/)(__pycache__|node_modules)(/|$)"
)

# Debug residue in shipped code. `console.warn` is deliberate — the two uses in
# the extension are genuine degraded-mode reports a user may be asked for — so
# only the noisier calls are refused.
DEBUG_CALLS = re.compile(r"\bconsole\.(log|debug|trace|dir)\s*\(|\bdebugger\b|sourceMappingURL")

# Every file has to be reachable from one of these, directly or through an
# import. Unreferenced files are the ones that quietly accumulate.
ENTRY_POINTS = ("manifest.json",)


def collect_files():
    """Every file under extension/ that belongs in the package, sorted."""
    kept = []
    for path in sorted(SOURCE.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(SOURCE).as_posix()
        if EXCLUDE.search(relative):
            continue
        kept.append((relative, path))
    return kept


def check_manifest(manifest):
    """The rejections that come back from the dashboard rather than a reviewer."""
    problems = []

    description = manifest.get("description", "")
    if not description:
        problems.append("manifest has no description")
    elif len(description) > MAX_DESCRIPTION:
        problems.append(
            f"description is {len(description)} characters, limit is {MAX_DESCRIPTION}"
        )

    version = manifest.get("version", "")
    # Chrome allows one to four dot-separated integers, each 0-65535, and the
    # store additionally refuses a version it has already seen.
    if not re.fullmatch(r"\d{1,5}(\.\d{1,5}){0,3}", version):
        problems.append(f"version {version!r} is not a valid Chrome version string")

    for size in REQUIRED_ICONS:
        if size not in manifest.get("icons", {}):
            problems.append(f"manifest declares no {size}px icon")

    return problems


def check_references(manifest, files):
    """Confirm the manifest's own file references resolve, and find orphans.

    Reference-following is textual: every path-shaped string in every shipped
    text file is treated as a reference. That over-matches rather than
    under-matches, which is the right direction — the point is to catch a file
    nothing points at, and a false "referenced" is merely a missed warning
    while a false "orphan" would block a legitimate build.
    """
    present = {relative for relative, _ in files}
    problems = []

    # Direct manifest references, which must exist or Chrome refuses to load.
    declared = set()
    for size, icon in {**manifest.get("icons", {}), **manifest.get("action", {}).get("default_icon", {})}.items():
        declared.add(icon)
    if popup := manifest.get("action", {}).get("default_popup"):
        declared.add(popup)
    if options := manifest.get("options_page"):
        declared.add(options)
    if worker := manifest.get("background", {}).get("service_worker"):
        declared.add(worker)
    for block in manifest.get("content_scripts", []):
        declared.update(block.get("js", []))
        declared.update(block.get("css", []))

    for reference in sorted(declared):
        if reference not in present:
            problems.append(f"manifest references {reference}, which is not in the package")

    # Anything the shipped text files mention by name counts as reached.
    mentioned = set()
    for relative, path in files:
        if path.suffix not in {".js", ".html", ".css", ".json"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name in present:
            if name == relative:
                continue
            # Match on the basename too: imports are written relative to the
            # importing file ("../lib/storage.js"), not to extension/.
            if name in text or pathlib.PurePosixPath(name).name in text:
                mentioned.add(name)

    orphans = present - mentioned - declared - set(ENTRY_POINTS)
    for orphan in sorted(orphans):
        problems.append(f"{orphan} is in the package but nothing references it")

    return problems


def check_debug_residue(files):
    problems = []
    for relative, path in files:
        if path.suffix not in {".js", ".html"}:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if DEBUG_CALLS.search(line):
                problems.append(f"{relative}:{number} looks like debug residue: {line.strip()[:70]}")
    return problems


def write_zip(target, files):
    """Write the package deterministically.

    Fixed timestamps and sorted entries mean two builds of the same commit
    produce byte-identical zips, so "is what I uploaded what is in git" is a
    checksum comparison rather than an act of faith.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative, path in files:
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())


def main():
    manifest_path = SOURCE / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    files = collect_files()
    print(f"packaging {len(files)} files from {SOURCE.relative_to(ROOT)}/")

    problems = (
        check_manifest(manifest)
        + check_references(manifest, files)
        + check_debug_residue(files)
    )
    if problems:
        print()
        for problem in problems:
            print(f"  ! {problem}")
        raise SystemExit(f"\n{len(problems)} problem(s) — refusing to write a package")

    target = DIST / f"baitwatch-{manifest['version']}.zip"
    write_zip(target, files)

    size_kb = target.stat().st_size / 1024
    largest = max(files, key=lambda pair: pair[1].stat().st_size)
    print(f"  wrote {target.relative_to(ROOT)} ({size_kb:.0f} KB)")
    print(f"  largest entry: {largest[0]} ({largest[1].stat().st_size / 1024:.0f} KB)")
    print("  checks passed: manifest limits, file references, no debug residue")


if __name__ == "__main__":
    main()
