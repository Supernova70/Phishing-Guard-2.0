# Monochrome globe textures

These assets are generated from public-domain NASA Earth imagery and a
land/water mask distributed with the MIT-licensed `three-globe` examples.

| File | Purpose | Source |
| --- | --- | --- |
| `earth-monochrome.webp` | 4K neutral albedo | [NASA Blue Marble Next Generation, December 2004](https://eoimages.gsfc.nasa.gov/images/imagerecords/74000/74218/world.200412.3x5400x2700.jpg) |
| `earth-monochrome-normal.png` | 4K tangent-space terrain normals | [NASA/NOAA GEBCO-derived elevation](https://eoimages.gsfc.nasa.gov/images/imagerecords/73000/73934/gebco_08_rev_elev_21600x10800.png) |
| `earth-monochrome-roughness.png` | Ocean/land roughness breakup | Derived from the same elevation and land/water mask |
| Source mask | Coastline masking during generation | [`three-globe` example `earth-water.png`](https://unpkg.com/three-globe/example/img/earth-water.png) |

NASA Earth Observatory imagery is generally free to use; see the
[NASA media usage guidelines](https://www.nasa.gov/nasa-brand-center/images-and-media/).
The derived textures are neutral grayscale and contain no NASA branding.

Regenerate with:

```bash
python3 -m venv /tmp/globe-texture-env
/tmp/globe-texture-env/bin/pip install pillow numpy
/tmp/globe-texture-env/bin/python frontend/scripts/build-globe-textures.py
```

The source files are downloaded into `GLOBE_TEXTURE_WORKDIR`
(default `/tmp/phishnet-globe-textures`) on first run.
