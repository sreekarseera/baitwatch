"""Generate the extension's toolbar icons.

Kept in the repo (rather than committing only the PNGs) so the mark can be
regenerated at any size without a design tool. Run from training/:

    python3 make_icons.py
"""

import os

from PIL import Image, ImageDraw

OUT_DIR = os.path.join("..", "extension", "icons")
SIZES = (16, 48, 128)

INK = (22, 22, 26, 255)      # near-black shield
PAPER = (255, 255, 255, 0)   # transparent background
MARK = (255, 255, 255, 255)  # the check/slash inside


def shield_points(size: int):
    """A rounded shield outline scaled to `size`."""
    w = h = size
    pad = size * 0.09
    top = pad
    bottom = h - pad
    left = pad
    right = w - pad
    shoulder = top + (bottom - top) * 0.55

    return [
        (w / 2, top),
        (right, top + (bottom - top) * 0.12),
        (right, shoulder),
        (w / 2, bottom),
        (left, shoulder),
        (left, top + (bottom - top) * 0.12),
    ]


def draw_icon(size: int) -> Image.Image:
    # Supersample 8x and downscale — Pillow has no antialiased polygon fill,
    # and at 16px the aliasing is the difference between a crisp mark and mush.
    scale = 8
    big = size * scale
    img = Image.new("RGBA", (big, big), PAPER)
    draw = ImageDraw.Draw(img)

    draw.polygon(shield_points(big), fill=INK)

    # Checkmark, proportional to the shield.
    cx, cy = big / 2, big * 0.47
    unit = big * 0.115
    width = max(2, int(big * 0.075))
    draw.line(
        [
            (cx - unit * 1.05, cy),
            (cx - unit * 0.15, cy + unit * 0.85),
            (cx + unit * 1.15, cy - unit * 0.95),
        ],
        fill=MARK,
        width=width,
        joint="curve",
    )

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    for size in SIZES:
        path = os.path.join(OUT_DIR, f"icon{size}.png")
        draw_icon(size).save(path, "PNG")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
