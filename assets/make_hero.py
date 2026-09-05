"""Generate the Drosera hero and social images.

    python assets/make_hero.py

Composed programmatically rather than drawn by hand so everything stays
consistent with the icon: the bead motif, the accent colour and the
proportions all come from the same numbers.

Two constraints shaped the layouts. These images are Open Graph cards as well
as heroes, so they spend most of their lives as thumbnails a couple of hundred
pixels wide in feeds and link previews -- the wordmark has to survive heavy
downscaling and the composition cannot lean on fine detail. And they sit next
to the post title, so the picture should carry the *idea* rather than repeat
the headline.

The idea is the last bead: everything on the strand is bait, and one of them
has caught something.

Each aspect ratio gets its own strand and type block rather than a crop of the
landscape one. A 1.91:1 diagonal does not survive being squared -- the sweep
either flattens out or runs off the canvas, and the text ends up fighting the
artwork for the same pixels.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:  # pragma: no cover
    print("Pillow is required: pip install pillow", file=sys.stderr)
    raise SystemExit(1) from None

HERE = Path(__file__).resolve().parent
FONTS = Path("C:/Windows/Fonts")

SS = 2                    # supersample for smooth circles

BG_TOP = (18, 18, 24)
BG_BOT = (11, 11, 15)
INK = (109, 74, 255)
INK_SOFT = (140, 112, 255)
SPECK = (14, 12, 26)
TEXT = (242, 239, 230)
MUTED = (150, 146, 160)

BODY = "An open-source honeypot that tells LLM-driven\nclients apart from ordinary bots."


@dataclass
class Layout:
    name: str
    w: int
    h: int
    strand: list[tuple[int, int, int]]      # (x, y, radius), climbing left to right
    x: int                                   # left margin of the type block
    title_y: int
    title_size: int
    tag_y: int
    tag_size: int
    body_y: int
    body_size: int
    rule_y: int
    rule_w: int
    glow: int = 38
    thumb: tuple[int, int] = (480, 251)
    body_text: str = BODY
    stem_w: int = 3
    checks: list[str] = field(default_factory=list)


LAYOUTS = [
    Layout(
        name="hero",                         # Substack header, OG card
        w=1600, h=838,
        strand=[(600, 780, 6), (720, 715, 9), (845, 645, 13), (975, 568, 18),
                (1110, 484, 25), (1250, 390, 35), (1385, 280, 49), (1500, 155, 72)],
        x=118, title_y=300, title_size=108,
        tag_y=432, tag_size=34,
        body_y=500, body_size=27,
        rule_y=596, rule_w=300,
        thumb=(480, 251),
    ),
    Layout(
        name="social-square",                # LinkedIn and X feed posts
        w=1200, h=1200,
        # A square wants a steeper sweep confined to the upper two thirds, with
        # the type stacked underneath rather than beside it.
        strand=[(150, 690, 7), (268, 620, 11), (395, 545, 16), (530, 462, 23),
                (672, 372, 32), (812, 285, 44), (945, 195, 58), (1062, 108, 76)],
        x=100, title_y=812, title_size=112,
        tag_y=952, tag_size=36,
        body_y=1022, body_size=27,
        rule_y=1118, rule_w=300,
        glow=44,
        thumb=(300, 300),
        stem_w=3,
    ),
    Layout(
        name="x-card",                       # X summary_large_image link card
        w=1200, h=628,
        strand=[(470, 588, 5), (580, 534, 8), (695, 474, 12), (815, 408, 17),
                (930, 336, 24), (1010, 262, 34), (1108, 145, 56)],
        x=100, title_y=196, title_size=92,
        tag_y=312, tag_size=30,
        body_y=0, body_size=22,
        rule_y=392, rule_w=260,
        glow=32,
        thumb=(500, 262),
        body_text="",     # deliberately omitted: unreadable at card size
        stem_w=2,
    ),
]


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size)


def background(L: Layout) -> Image.Image:
    img = Image.new("RGB", (L.w, L.h), BG_BOT)
    d = ImageDraw.Draw(img)
    for y in range(L.h):
        t = y / L.h
        d.line([(0, y), (L.w, y)],
               fill=tuple(int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3)))
    return img


def strand_layer(L: Layout, glow: bool) -> Image.Image:
    layer = Image.new("RGBA", (L.w * SS, L.h * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)

    if not glow:
        pts = []
        for i in range(len(L.strand) - 1):
            x0, y0, _ = L.strand[i]
            x1, y1, _ = L.strand[i + 1]
            for k in range(24):
                t = k / 24
                pts.append(((x0 + (x1 - x0) * t) * SS, (y0 + (y1 - y0) * t) * SS))
        d.line(pts, fill=(*INK, 70), width=L.stem_w * SS, joint="curve")

    for i, (x, y, r) in enumerate(L.strand):
        rr = (r * (2.6 if glow else 1.0)) * SS
        # Later beads are brighter: the eye should travel toward the catch.
        alpha = int(28 + 34 * (i / (len(L.strand) - 1))) if glow else 255
        colour = INK_SOFT if i >= len(L.strand) - 2 else INK
        d.ellipse([x * SS - rr, y * SS - rr, x * SS + rr, y * SS + rr], fill=(*colour, alpha))

    layer = layer.resize((L.w, L.h), Image.LANCZOS)
    return layer.filter(ImageFilter.GaussianBlur(L.glow)) if glow else layer


def speck_layer(L: Layout) -> Image.Image:
    """The gnat, in the last bead. The whole point of the picture.

    An abdomen and a head. An earlier version had legs, which at this scale
    read as clock hands and vanished in the thumbnail regardless.
    """
    layer = Image.new("RGBA", (L.w * SS, L.h * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    x, y, r = L.strand[-1]
    cx, cy = (x + r * 0.14) * SS, (y - r * 0.12) * SS
    br = r * 0.21 * SS
    d.ellipse([cx - br * 1.35, cy - br * 0.82, cx + br * 1.35, cy + br * 0.82], fill=(*SPECK, 255))
    hr = br * 0.62
    d.ellipse([cx + br * 1.05 - hr, cy - br * 0.72 - hr,
               cx + br * 1.05 + hr, cy - br * 0.72 + hr], fill=(*SPECK, 255))
    return layer.resize((L.w, L.h), Image.LANCZOS)


def compose(L: Layout) -> Image.Image:
    img = background(L).convert("RGBA")
    img.alpha_composite(strand_layer(L, glow=True))
    img.alpha_composite(strand_layer(L, glow=False))
    img.alpha_composite(speck_layer(L))

    d = ImageDraw.Draw(img)
    d.text((L.x, L.title_y), "DROSERA", font=font("segoeuib.ttf", L.title_size), fill=TEXT)
    d.text((L.x + 6, L.tag_y), "Sweet-looking bait.  Sticky ending.",
           font=font("segoeuisl.ttf", L.tag_size), fill=INK_SOFT)
    if L.body_text:
        d.text((L.x + 6, L.body_y), L.body_text,
               font=font("segoeuisl.ttf", L.body_size), fill=MUTED, spacing=10)
    d.line([(L.x + 6, L.rule_y), (L.x + 6 + L.rule_w, L.rule_y)], fill=(*INK, 120), width=2)
    d.text((L.x + 6, L.rule_y + 26), "droseraproject.org",
           font=font("consola.ttf", max(20, L.body_size - 3)), fill=MUTED)
    return img.convert("RGB")


def clipped(L: Layout) -> list[str]:
    """Flag beads running off the canvas.

    The final bead carries the catch, which is the payoff of the whole image.
    Letting the edge crop it is a quiet way to lose the point.
    """
    out = []
    for x, y, r in L.strand:
        if x - r < 0 or y - r < 0 or x + r > L.w or y + r > L.h:
            out.append(f"bead at ({x},{y}) r{r} is clipped by the canvas edge")
    return out


def overlaps_text(L: Layout) -> list[str]:
    """Flag beads that land in the type block.

    The first landscape draft ran the strand straight through the body copy;
    this makes that mistake fail loudly instead of needing a second look.
    """
    top = L.title_y - 10
    bottom = L.rule_y + 60
    widest = 660 if L.body_text else 420
    right = L.x + 6 + max(L.rule_w, widest)
    clashes = []
    for x, y, r in L.strand:
        if top < y + r and y - r < bottom and x - r < right:
            clashes.append(f"bead at ({x},{y}) r{r} overlaps the type block")
    return clashes


def main() -> None:
    problems = []
    for L in LAYOUTS:
        problems += [f"{L.name}: {c}" for c in overlaps_text(L) + clipped(L)]
        img = compose(L)
        img.save(HERE / f"{L.name}.png", optimize=True)
        img.resize(L.thumb, Image.LANCZOS).save(HERE / f"{L.name}-thumb.png", optimize=True)
        kb = (HERE / f"{L.name}.png").stat().st_size // 1024
        print(f"  {L.name}.png  {L.w}x{L.h}  {kb} KB   (thumb {L.thumb[0]}x{L.thumb[1]})")

    if problems:
        print("\n  LAYOUT PROBLEMS:")
        for p in problems:
            print(f"    {p}")
        raise SystemExit(1)
    print("  no bead/text collisions, nothing clipped")


if __name__ == "__main__":
    main()
