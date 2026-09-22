"""Generate the hero image for the 0.2 announcement post.

    python assets/make_blog_hero.py

Same family as make_hero.py, and built from its pieces -- background, strand,
glow and gnat all come from there, so the two images cannot drift apart.

The 0.2 idea is what happens *after* the catch. The last bead still holds the
gnat; a trail of droplets now carries the evidence out of it and into a stack
of incident cards. Honeypot to SOC, without leaning on anyone's logo: the cards
are abstract on purpose, and product names appear only as words in the copy.
"""

from __future__ import annotations

from dataclasses import dataclass

from make_hero import (
    HERE,
    INK,
    INK_SOFT,
    MUTED,
    SS,
    TEXT,
    Image,
    ImageDraw,
    ImageFilter,
    Layout,
    background,
    clipped,
    font,
    overlaps_text,
    speck_layer,
    strand_layer,
)

PANEL = (30, 29, 40)
PANEL_EDGE = (58, 52, 88)
BAR = (86, 82, 104)
CONFIRMED = (236, 131, 90)   # the report's "high/confirmed" warm accent, not a series colour
TITLE_BAR = 150              # right edge of the card's title line, from the card's left


@dataclass
class Card:
    x: int
    y: int
    w: int
    h: int
    alpha: int
    front: bool = False


L = Layout(
    name="blog-0.2-hero",
    w=1600, h=838,
    strand=[(560, 800, 6), (668, 742, 9), (780, 676, 13), (895, 598, 18),
            (1000, 508, 25), (1085, 405, 35), (1140, 262, 58)],
    x=118, title_y=268, title_size=108,
    tag_y=400, tag_size=38,
    body_y=470, body_size=27,
    rule_y=566, rule_w=300,
    glow=36,
    body_text="Evidence from the bait, straight into\nMicrosoft Sentinel and Defender.",
)

# Back to front. The stack recedes down and to the right, so the trail can land
# on the front card's top edge without crossing the others.
CARDS = [
    Card(1252, 518, 316, 92, alpha=90),
    Card(1236, 494, 316, 92, alpha=150),
    Card(1220, 470, 316, 92, alpha=255, front=True),
]


def trail() -> list[tuple[float, float, float]]:
    """Droplets from the catch to the front card: a quadratic curve, shrinking."""
    bx, by, br = L.strand[-1]
    p0 = (bx + br * 0.72, by + br * 0.70)
    p2 = (CARDS[-1].x + 78, CARDS[-1].y - 9)
    p1 = (p2[0] - 10, p0[1] + 20)
    out = []
    n = 8
    for i in range(n):
        t = (i + 1) / n
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        out.append((x, y, 7.5 - 4.0 * t))
    return out


def trail_layer(glow: bool) -> Image.Image:
    layer = Image.new("RGBA", (L.w * SS, L.h * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for x, y, r in trail():
        rr = r * (2.4 if glow else 1.0) * SS
        d.ellipse([x * SS - rr, y * SS - rr, x * SS + rr, y * SS + rr],
                  fill=(*INK_SOFT, 60 if glow else 235))
    layer = layer.resize((L.w, L.h), Image.LANCZOS)
    return layer.filter(ImageFilter.GaussianBlur(14)) if glow else layer


def cards_layer() -> Image.Image:
    layer = Image.new("RGBA", (L.w * SS, L.h * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    s = SS
    for c in CARDS:
        a = c.alpha
        box = [c.x * s, c.y * s, (c.x + c.w) * s, (c.y + c.h) * s]
        d.rounded_rectangle(box, radius=14 * s, fill=(*PANEL, a), outline=(*PANEL_EDGE, a), width=2 * s)
        if not c.front:
            continue
        # Accent spine: this incident came from Drosera.
        d.rounded_rectangle([c.x * s, c.y * s, (c.x + 7) * s, (c.y + c.h) * s],
                            radius=4 * s, fill=(*INK, 255))
        # Abstract text lines -- a title and a detail row.
        d.rounded_rectangle([(c.x + 30) * s, (c.y + 26) * s, (c.x + TITLE_BAR) * s, (c.y + 38) * s],
                            radius=6 * s, fill=(*TEXT, 210))
        d.rounded_rectangle([(c.x + 30) * s, (c.y + 54) * s, (c.x + 30 + int(TITLE_BAR * 0.62)) * s, (c.y + 64) * s],
                            radius=5 * s, fill=(*BAR, 255))
    return layer.resize((L.w, L.h), Image.LANCZOS)


def card_glow() -> Image.Image:
    layer = Image.new("RGBA", (L.w, L.h), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    c = CARDS[-1]
    d.rounded_rectangle([c.x - 10, c.y - 10, c.x + c.w + 30, c.y + c.h + 60], radius=30,
                        fill=(*INK, 46))
    return layer.filter(ImageFilter.GaussianBlur(34))


def compose() -> Image.Image:
    img = background(L).convert("RGBA")
    img.alpha_composite(strand_layer(L, glow=True))
    img.alpha_composite(card_glow())
    img.alpha_composite(trail_layer(glow=True))
    img.alpha_composite(strand_layer(L, glow=False))
    img.alpha_composite(speck_layer(L))
    img.alpha_composite(trail_layer(glow=False))
    img.alpha_composite(cards_layer())

    d = ImageDraw.Draw(img)
    c = CARDS[-1]
    # The verdict pill on the front card: the one piece of text in the artwork,
    # because "confirmed" is the idea the whole release carries through.
    pill_font = font("consola.ttf", 19)
    label = "confirmed"
    tw = d.textlength(label, font=pill_font)
    px1 = c.x + c.w - 22
    px0 = px1 - tw - 26
    py0, py1 = c.y + 18, c.y + 50
    d.rounded_rectangle([px0, py0, px1, py1], radius=16, outline=CONFIRMED, width=2)
    d.text(((px0 + px1) / 2, (py0 + py1) / 2), label, font=pill_font, fill=CONFIRMED, anchor="mm")
    if px0 < c.x + TITLE_BAR + 16:
        raise SystemExit(f"LAYOUT PROBLEM: the verdict pill (x={px0:.0f}) overlaps the card's title line")

    title_font = font("segoeuib.ttf", L.title_size)
    d.text((L.x, L.title_y), "DROSERA", font=title_font, fill=TEXT)
    tw = d.textlength("DROSERA", font=title_font)
    d.text((L.x + tw + 22, L.title_y + 44), "0.2", font=font("segoeuisl.ttf", 58), fill=INK_SOFT)
    d.text((L.x + 6, L.tag_y), "From honeypot to SOC.", font=font("segoeuisl.ttf", L.tag_size), fill=INK_SOFT)
    d.text((L.x + 6, L.body_y), L.body_text, font=font("segoeuisl.ttf", L.body_size), fill=MUTED, spacing=10)
    d.line([(L.x + 6, L.rule_y), (L.x + 6 + L.rule_w, L.rule_y)], fill=(*INK, 120), width=2)
    d.text((L.x + 6, L.rule_y + 26), "droseraproject.org", font=font("consola.ttf", 24), fill=MUTED)
    return img.convert("RGB")


def card_problems() -> list[str]:
    out = []
    right_of_text = L.x + 6 + 660
    for c in CARDS:
        if c.x < right_of_text and c.y < L.rule_y + 60 and c.y + c.h > L.title_y:
            out.append(f"card at ({c.x},{c.y}) overlaps the type block")
        if c.x + c.w > L.w - 20 or c.y + c.h > L.h - 20:
            out.append(f"card at ({c.x},{c.y}) runs off the canvas")
    bx, by, br = L.strand[-1]
    for x, y, r in trail():
        if (x - bx) ** 2 + (y - by) ** 2 < (br + r) ** 2:
            out.append(f"trail droplet at ({x:.0f},{y:.0f}) sits inside the catch bead")
    return out


def main() -> None:
    problems = overlaps_text(L) + clipped(L) + card_problems()
    img = compose()
    img.save(HERE / f"{L.name}.png", optimize=True)
    img.resize(L.thumb, Image.LANCZOS).save(HERE / f"{L.name}-thumb.png", optimize=True)
    kb = (HERE / f"{L.name}.png").stat().st_size // 1024
    print(f"  {L.name}.png  {L.w}x{L.h}  {kb} KB   (thumb {L.thumb[0]}x{L.thumb[1]})")
    if problems:
        print("\n  LAYOUT PROBLEMS:")
        for p in problems:
            print(f"    {p}")
        raise SystemExit(1)
    print("  no collisions, nothing clipped")


if __name__ == "__main__":
    main()
