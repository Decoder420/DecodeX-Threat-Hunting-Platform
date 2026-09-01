#!/usr/bin/env python3
"""
generate_brand_assets.py
Processes the new DecodeX & DX logo design formats and distributes them to all
appropriate locations in the frontend and backend assets directories.
"""

import os
from pathlib import Path
from PIL import Image

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

# Source raw images uploaded by user
SRC_EMBLEM = Path("/Users/manan/.gemini/antigravity-ide/brain/b19c27c8-ac85-424f-8eb7-bde36da92977/.user_uploaded/media_1788247783851.png")
SRC_WORDMARK = Path("/Users/manan/.gemini/antigravity-ide/brain/b19c27c8-ac85-424f-8eb7-bde36da92977/.user_uploaded/media_1788247783867.png")
SRC_COMBINED = Path("/Users/manan/.gemini/antigravity-ide/brain/b19c27c8-ac85-424f-8eb7-bde36da92977/.user_uploaded/media_1788247783880.png")

DEST_DIRS = [
    WORKSPACE_ROOT / "frontend" / "public",
    WORKSPACE_ROOT / "backend" / "src" / "th" / "assets",
    WORKSPACE_ROOT / "DecodeX-Threat-Hunting-Platform" / "frontend" / "public",
    WORKSPACE_ROOT / "DecodeX-Threat-Hunting-Platform" / "backend" / "src" / "th" / "assets",
]


def crop_tight(img: Image.Image) -> Image.Image:
    """Strip transparent padding to bounds of actual visible pixels."""
    bbox = img.getbbox()
    if bbox:
        return img.crop(bbox)
    return img


def make_square_icon(img: Image.Image, size: int = 512, padding_pct: float = 0.08) -> Image.Image:
    """Center image within a square canvas with balanced margin."""
    cropped = crop_tight(img)
    target_max = int(size * (1 - 2 * padding_pct))
    w, h = cropped.size
    scale = min(target_max / w, target_max / h)
    new_w, new_h = max(1, int(w * scale)), max(1, int(h * scale))
    resized = cropped.resize((new_w, new_h), Image.Resampling.LANCZOS)

    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset_x = (size - new_w) // 2
    offset_y = (size - new_h) // 2
    canvas.paste(resized, (offset_x, offset_y), resized)
    return canvas


def make_favicon(img: Image.Image, out_path: Path):
    """Generate multi-resolution .ico containing 16x16, 32x32, 48x48, 64x64."""
    cropped = crop_tight(img)
    base_icon = make_square_icon(cropped, size=64, padding_pct=0.04)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    base_icon.save(
        out_path,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64)],
    )


def generate_all():
    print(f"Loading source images...")
    emblem_raw = Image.open(SRC_EMBLEM).convert("RGBA")
    wordmark_raw = Image.open(SRC_WORDMARK).convert("RGBA")
    combined_raw = Image.open(SRC_COMBINED).convert("RGBA")

    # Tight crops
    emblem_tight = crop_tight(emblem_raw)
    wordmark_tight = crop_tight(wordmark_raw)
    combined_tight = crop_tight(combined_raw)

    print(f"Emblem tight crop: {emblem_tight.size}")
    print(f"Wordmark tight crop: {wordmark_tight.size}")
    print(f"Combined tight crop: {combined_tight.size}")

    # Square icons
    icon_192 = make_square_icon(emblem_raw, size=192, padding_pct=0.07)
    icon_512 = make_square_icon(emblem_raw, size=512, padding_pct=0.07)

    for dest in DEST_DIRS:
        if not dest.parent.exists():
            continue
        dest.mkdir(parents=True, exist_ok=True)
        print(f"\nWriting brand assets to {dest} ...")

        # 1. DX Emblem / Icon
        emblem_tight.save(dest / "decodex_emblem.png", format="PNG", optimize=True)
        emblem_tight.save(dest / "decodex_icon.png", format="PNG", optimize=True)

        # 2. Horizontal Wordmark
        wordmark_tight.save(dest / "decodex_wordmark.png", format="PNG", optimize=True)

        # 3. Combined Lockup / Hero Badge
        combined_tight.save(dest / "decodex_logo.png", format="PNG", optimize=True)
        combined_tight.save(dest / "decodex_transparent.png", format="PNG", optimize=True)

        # 4. Square Icons (logo192 / logo512)
        icon_192.save(dest / "logo192.png", format="PNG", optimize=True)
        icon_512.save(dest / "logo512.png", format="PNG", optimize=True)

        # 5. Favicon
        make_favicon(emblem_raw, dest / "favicon.ico")

    print("\n✅ All brand assets successfully generated and synced across platform!")


if __name__ == "__main__":
    generate_all()
