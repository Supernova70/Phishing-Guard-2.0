#!/usr/bin/env python3
"""Build the monochrome Earth textures used by the light-mode globe.

The inputs are public-domain NASA Earth imagery plus the land/water mask
distributed with the MIT-licensed three-globe examples:
  * Blue Marble Next Generation (December 2004), NASA Earth Observatory
  * GEBCO-derived global elevation, NASA Earth Observatory
  * earth-water.png from three-globe

Run this only when the source textures change. The generated files are
committed to frontend/public/textures and served as static assets.
"""
import os
from pathlib import Path
from urllib.request import urlretrieve

import numpy as np
from PIL import Image, ImageFilter

Image.MAX_IMAGE_PIXELS = None

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "textures"
WORK = Path(os.environ.get("GLOBE_TEXTURE_WORKDIR", "/tmp/phishnet-globe-textures"))

SOURCE_URLS = {
    "blue-marble-5400.jpg": "https://eoimages.gsfc.nasa.gov/images/imagerecords/74000/74218/world.200412.3x5400x2700.jpg",
    "gebco-topo-21600.png": "https://eoimages.gsfc.nasa.gov/images/imagerecords/73000/73934/gebco_08_rev_elev_21600x10800.png",
    "earth-water.png": "https://unpkg.com/three-globe/example/img/earth-water.png",
}

ALBEDO_SIZE = (4096, 2048)
NORMAL_SIZE = (4096, 2048)
ROUGHNESS_SIZE = (1024, 512)

DAY = WORK / "blue-marble-5400.jpg"
TOPO = WORK / "gebco-topo-21600.png"
WATER = WORK / "earth-water.png"

# Land is deliberately a restrained silver/graphite range. Oceans sit near
# black charcoal so the globe reads as a sculpted object on white.
LAND_FLOOR = 0.20
LAND_RANGE = 0.74
ELEVATION_LIFT = 0.10
OCEAN_TONE = 0.130
OCEAN_HIGHLIGHT = 0.026


def ensure_sources() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    for filename, url in SOURCE_URLS.items():
        destination = WORK / filename
        if destination.exists():
            continue
        print(f"Downloading {filename}…")
        urlretrieve(url, destination)


def resized_gray(path: Path, size: tuple[int, int]) -> Image.Image:
    return Image.open(path).convert("L").resize(size, Image.Resampling.LANCZOS)


def build_albedo() -> None:
    size = ALBEDO_SIZE
    day = np.asarray(
        Image.open(DAY).convert("RGB").resize(size, Image.Resampling.LANCZOS),
        dtype=np.float32,
    ) / 255.0
    water = np.asarray(
        Image.open(WATER).convert("L").resize(size, Image.Resampling.LANCZOS),
        dtype=np.float32,
    ) / 255.0
    topo = np.asarray(resized_gray(TOPO, size), dtype=np.float32) / 255.0

    lum = 0.2126 * day[..., 0] + 0.7152 * day[..., 1] + 0.0722 * day[..., 2]
    land = np.clip(1.0 - water, 0.0, 1.0)

    # Normalise terrestrial elevation to the range actually occupied by land.
    h = np.clip((topo - 0.006) / 0.58, 0.0, 1.0)
    land_tone = LAND_FLOOR + LAND_RANGE * np.power(lum, 1.06) + ELEVATION_LIFT * h
    land_tone = np.clip(land_tone, 0.18, 0.985)

    # Ocean stays nearly black with only the faintest slate variation.
    ocean_tone = OCEAN_TONE + OCEAN_HIGHLIGHT * np.clip(lum / 0.12, 0.0, 1.0)

    # Soften the coastline by one pixel so the land/ocean edge does not alias.
    land_soft = np.asarray(
        Image.fromarray((land * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(0.7)),
        dtype=np.float32,
    ) / 255.0
    tone = ocean_tone * (1.0 - land_soft) + land_tone * land_soft
    tone = np.clip(tone, 0.0, 1.0)
    rgb = np.repeat(tone[..., None], 3, axis=2)
    Image.fromarray((rgb * 255).round().astype(np.uint8), "RGB").save(
        OUT / "earth-monochrome.webp", quality=92, method=6
    )


def build_normal() -> None:
    size = NORMAL_SIZE
    topo = resized_gray(TOPO, size).filter(ImageFilter.GaussianBlur(1.1))
    h = np.asarray(topo, dtype=np.float32) / 255.0
    water = np.asarray(
        Image.open(WATER).convert("L").resize(size, Image.Resampling.LANCZOS),
        dtype=np.float32,
    ) / 255.0
    land = np.clip(1.0 - water, 0.0, 1.0)

    # Central differences, wrapped across the date line.
    dx = (np.roll(h, -1, axis=1) - np.roll(h, 1, axis=1)) * 0.5
    dy = (np.roll(h, -1, axis=0) - np.roll(h, 1, axis=0)) * 0.5
    strength = 30.0
    nx = -dx * strength * land
    ny = dy * strength * land
    nz = np.ones_like(nx)
    inv = 1.0 / np.sqrt(nx * nx + ny * ny + nz * nz)

    normal = np.stack((nx * inv, ny * inv, nz * inv), axis=-1)
    encoded = (normal * 0.5 + 0.5) * 255.0
    Image.fromarray(encoded.round().astype(np.uint8), "RGB").save(
        OUT / "earth-monochrome-normal.png", optimize=True
    )


def build_roughness() -> None:
    size = ROUGHNESS_SIZE
    water = np.asarray(
        Image.open(WATER).convert("L").resize(size, Image.Resampling.LANCZOS),
        dtype=np.float32,
    ) / 255.0
    land = np.clip(1.0 - water, 0.0, 1.0)
    # Oceans are smoother (more ceramic highlight); land is matte.
    roughness = 0.34 * (1.0 - land) + 0.70 * land
    Image.fromarray((roughness * 255).round().astype(np.uint8), "L").save(
        OUT / "earth-monochrome-roughness.png", optimize=True
    )


def main() -> None:
    ensure_sources()
    OUT.mkdir(parents=True, exist_ok=True)
    build_albedo()
    build_normal()
    build_roughness()
    for path in sorted(OUT.iterdir()):
        if path.is_file():
            print(f"{path.name}: {path.stat().st_size / 1024:.1f} KiB")


if __name__ == "__main__":
    main()
