"""Generate the hero / social-card image for the Drosera launch post.

    python assets/make_hero.py

Composed programmatically rather than drawn by hand so it stays consistent
with the icon: the bead motif, the accent colour and the proportions all come
from the same numbers.

Two constraints shaped the layout. A Substack hero is also the Open Graph card,
so it gets rendered as a thumbnail a couple of hundred pixels wide in feeds and
link previews -- which means the wordmark has to survive heavy downscaling and
the composition cannot rely on fine detail. And it is seen next to the article
title, so the image should carry the *idea*, not repeat the headline.

The idea here is the last bead: everything on the strand is bait, and one of
them has caught something.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:  # pragma: no cover
    print("Pillow is required: pip install pillow", file=sys.stderr)
    raise SystemExit(1) from None

HERE = Path(__file__).resolve().parent
FONTS = Path("C:/Windows/Fonts")

W, H = 1600, 838          # 1.91:1, the Open Graph ratio
SS = 2                    # supersample for smooth circles

BG_TOP = (18, 18, 24)
BG_BOT = (11, 11, 15)
INK = (109, 74, 255)
INK_SOFT = (140, 112, 255)
SPECK = (14, 12, 26)
TEXT = (242, 239, 230)
MUTED = (150, 146, 160)

# The strand: (x, y, radius) in final-image pixels, climbing left to right.
# Same shape language as the icon, stretched to a landscape sweep.
STRAND = [
    (600, 780, 6),
    (720, 715, 9),
    (845, 645, 13),
    (975, 568, 18),
    (1110, 484, 25),
    (1250, 390, 35),
    (1385, 280, 49),
    (1500, 155, 72),   # the one that caught something
]


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size)


def background() -> Image.Image:
    img = Image.new("RGB", (W, H), BG_BOT)
    d = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        d.line(
            [(0, y), (W, y)],
            fill=tuple(int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3)),
        )
    return img


def strand_layer(glow: bool) -> Image.Image:
    """Draw the beads, optionally as a blurred glow pass underneath."""
    layer = Image.new("RGBA", (W * SS, H * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    if not glow:
        # The leaf edge the beads sit on: faint, and only under the beads.
        pts = []
        for i in range(len(STRAND) - 1):
            x0, y0, _ = STRAND[i]
            x1, y1, _ = STRAND[i + 1]
            for k in range(24):
                t = k / 24
                pts.append(((x0 + (x1 - x0) * t) * SS, (y0 + (y1 - y0) * t) * SS))
        d.line(pts, fill=(*INK, 70), width=3 * SS, joint="curve")

    for i, (x, y, r) in enumerate(STRAND):
        rr = (r * (2.6 if glow else 1.0)) * SS
        # Later beads are brighter: the eye should travel toward the catch.
        alpha = int(28 + 34 * (i / (len(STRAND) - 1))) if glow else 255
        colour = INK_SOFT if i >= len(STRAND) - 2 else INK
        d.ellipse(
            [x * SS - rr, y * SS - rr, x * SS + rr, y * SS + rr],
            fill=(*colour, alpha),
        )

    layer = layer.resize((W, H), Image.LANCZOS)
    if glow:
        layer = layer.filter(ImageFilter.GaussianBlur(38))
    return layer


def speck_layer() -> Image.Image:
    """The gnat, in the last bead. The whole point of the picture."""
    layer = Image.new("RGBA", (W * SS, H * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    x, y, r = STRAND[-1]
    cx, cy = (x + r * 0.14) * SS, (y - r * 0.12) * SS
    br = r * 0.21 * SS
    # Abdomen, tilted along the strand, then a smaller head above it.
    d.ellipse([cx - br * 1.35, cy - br * 0.82, cx + br * 1.35, cy + br * 0.82],
              fill=(*SPECK, 255))
    hr = br * 0.62
    d.ellipse([cx + br * 1.05 - hr, cy - br * 0.72 - hr,
               cx + br * 1.05 + hr, cy - br * 0.72 + hr], fill=(*SPECK, 255))
    return layer.resize((W, H), Image.LANCZOS)


def compose() -> Image.Image:
    img = background().convert("RGBA")
    img.alpha_composite(strand_layer(glow=True))
    img.alpha_composite(strand_layer(glow=False))
    img.alpha_composite(speck_layer())

    d = ImageDraw.Draw(img)
    x = 118

    d.text((x, 300), "DROSERA", font=font("segoeuib.ttf", 108), fill=TEXT)
    # Letterspaced small caps read as a subtitle rather than a second headline.
    sub = font("segoeuisl.ttf", 34)
    d.text((x + 6, 432), "Sweet-looking bait.  Sticky ending.", font=sub, fill=INK_SOFT)

    body = font("segoeuisl.ttf", 27)
    d.text(
        (x + 6, 500),
        "An open-source honeypot that tells LLM-driven clients\napart from ordinary bots.",
        font=body,
        fill=MUTED,
        spacing=10,
    )

    rule_y = 596
    d.line([(x + 6, rule_y), (x + 6 + 300, rule_y)], fill=(*INK, 120), width=2)
    d.text((x + 6, rule_y + 26), "droseraproject.org", font=font("consola.ttf", 24), fill=MUTED)

    return img.convert("RGB")


def main() -> None:
    hero = compose()
    hero.save(HERE / "hero.png", optimize=True)
    # A feed thumbnail is the real test of whether the composition survives.
    hero.resize((480, 251), Image.LANCZOS).save(HERE / "hero-thumb.png", optimize=True)
    print(f"assets/hero.png  {W}x{H}  {(HERE / 'hero.png').stat().st_size // 1024} KB")
    print("assets/hero-thumb.png  480x251  (feed-size check)")


if __name__ == "__main__":
    main()
