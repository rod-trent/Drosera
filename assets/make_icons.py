"""Generate the Drosera mark: one geometry definition, every output format.

    python assets/make_icons.py

The mark is a run of dew beads climbing a leaf edge -- four droplets growing
larger toward the tip, with a speck caught in the last one. That is the lure
and the catch in one shape.

It is built from circles on purpose. A favicon has to survive being drawn at
16 pixels, and circles are the only primitive that degrades gracefully at that
size; strokes turn to grey mush. So the beads carry the identity and the
connecting arc is decoration, drawn only at 32px and above where there is room
for it.

Two earlier attempts are worth recording so nobody repeats them. Three stalks
fanning from a common point read unmistakably as a trident -- a weapon shape,
which is exactly wrong for a project whose whole claim is that it detects and
delays rather than attacks. A single teardrop with a dot inside is a map pin,
the most over-used icon on the internet.

Geometry lives here rather than in a hand-written SVG so the vector and the
raster cannot drift: the .ico is rasterised from the numbers the .svg is
written from.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover
    print("Pillow is required: pip install pillow", file=sys.stderr)
    raise SystemExit(1) from None

HERE = Path(__file__).resolve().parent
WEB = HERE.parent / "web"

# --- geometry, on a 64x64 canvas ------------------------------------------

VIEW = 64

# (centre, radius) for each bead, climbing left-to-right and growing toward
# the tip. Positioned so the area-weighted centroid sits on the canvas centre --
# an off-centre mark reads as misaligned in a browser tab, where there is no
# surrounding context to correct for it.
BEADS = [
    ((6.6, 58.4), 2.3),
    ((16.1, 48.9), 3.2),
    ((26.7, 38.4), 4.5),
    ((40.5, 23.5), 7.8),
]

# The leaf edge the beads sit on. Decorative: omitted below ARC_MIN px, where
# a hairline would only muddy the beads.
ARC = ((2.4, 63.3), (20.3, 51.6), (40.5, 23.5))   # start, control, end
ARC_W = 1.7
ARC_MIN = 32

SPECK = (42.4, 21.2, 2.0)   # the gnat, in the last bead
SPECK_MIN = 32

INK = "#6D4AFF"          # single accent: legible on light and dark chrome
SPECK_INK = "#1B1633"


def bezier(p0, p1, p2, steps=48):
    out = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        out.append(
            (
                u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
                u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1],
            )
        )
    return out


# --- SVG -------------------------------------------------------------------


def svg(with_speck: bool = True, size: int | None = None) -> str:
    dim = f' width="{size}" height="{size}"' if size else ""
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VIEW} {VIEW}"{dim} '
        'role="img" aria-label="Drosera">',
        "<title>Drosera</title>",
        f'<path d="M{ARC[0][0]} {ARC[0][1]} Q{ARC[1][0]} {ARC[1][1]} {ARC[2][0]} {ARC[2][1]}" '
        f'fill="none" stroke="{INK}" stroke-width="{ARC_W}" stroke-linecap="round" opacity="0.55"/>',
        f'<g fill="{INK}">',
    ]
    for (cx, cy), r in BEADS:
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}"/>')
    parts.append("</g>")
    if with_speck:
        x, y, r = SPECK
        parts.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{SPECK_INK}"/>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


# --- raster ----------------------------------------------------------------


def raster(size: int, supersample: int = 8) -> Image.Image:
    """Draw at 8x and downsample: Pillow has no anti-aliased primitives."""
    s = size * supersample
    scale = s / VIEW
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    def pt(p):
        return (p[0] * scale, p[1] * scale)

    if size >= ARC_MIN:
        pts = [pt(p) for p in bezier(*ARC)]
        d.line(pts, fill=(0x6D, 0x4A, 0xFF, 140), width=max(1, int(round(ARC_W * scale))),
               joint="curve")

    for (cx, cy), r in BEADS:
        x, y = pt((cx, cy))
        rr = r * scale
        d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=INK)

    if size >= SPECK_MIN:
        x, y, r = SPECK
        cx, cy = pt((x, y))
        rr = r * scale
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=SPECK_INK)

    return img.resize((size, size), Image.LANCZOS)


def write_ico(path: Path, sizes=(16, 32, 48)) -> None:
    """Write a PNG-in-ICO container by hand (Pillow's own ICO is fine, but
    this keeps the exact PNGs we generated rather than re-encoding them)."""
    import io

    images = []
    for s in sizes:
        buf = io.BytesIO()
        raster(s).save(buf, format="PNG", optimize=True)
        images.append((s, buf.getvalue()))

    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for s, data in images:
        entries += struct.pack(
            "<BBBBHHII", s if s < 256 else 0, s if s < 256 else 0, 0, 0, 1, 32, len(data), offset
        )
        blobs += data
        offset += len(data)
    path.write_bytes(header + entries + blobs)


def main() -> None:
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / "logo.svg").write_text(svg(), encoding="utf-8", newline="\n")
    (HERE / "icon.svg").write_text(svg(with_speck=False), encoding="utf-8", newline="\n")

    for size in (16, 32, 48, 64, 128, 180, 512):
        raster(size).save(HERE / f"icon-{size}.png", optimize=True)

    write_ico(HERE / "favicon.ico")

    # The site needs the icon at its web root.
    if WEB.is_dir():
        (WEB / "favicon.ico").write_bytes((HERE / "favicon.ico").read_bytes())
        (WEB / "icon.svg").write_text(svg(with_speck=False), encoding="utf-8", newline="\n")
        (WEB / "apple-touch-icon.png").write_bytes((HERE / "icon-180.png").read_bytes())

    made = sorted(p.name for p in HERE.iterdir() if p.suffix in {".png", ".ico", ".svg"})
    print("assets/: " + ", ".join(made))
    print(f"favicon.ico: {(HERE / 'favicon.ico').stat().st_size} bytes")


if __name__ == "__main__":
    main()
