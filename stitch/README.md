# Stitch Design Bundle — Phishing-Guard 2.0

Drop-zone kit for Google Stitch's **"Start with your design"** dialog
(https://stitch.withgoogle.com → New project → Start with your design).

## What to drop where

| Stitch dialog field | File(s) from this folder |
|---|---|
| **Paste existing DESIGN.md** | contents of `DESIGN.md` (paste whole file, front-matter included) |
| **Drag and drop files** | `screenshots/*.png` (current production UI, 1440x900) and/or `logos/*.svg` |
| **Add website** | `https://phishing-guard.duckdns.org` — note: only the public login page is crawlable (dashboard is auth-gated); screenshots cover the rest |
| **Additional instructions** | contents of `ADDITIONAL-INSTRUCTIONS.md` |
| **.fig file** | none needed — we have no Figma source; Stitch can export *to* Figma later |

## Contents

```
stitch/
├── DESIGN.md                  # Live design system extracted from frontend/src/index.css
│                              # (validated: npx @google/design.md lint → 0 errors)
├── ADDITIONAL-INSTRUCTIONS.md # Revamp brief: constraints + design direction + page list
├── README.md                  # this file
├── logos/
│   ├── favicon.svg            # shield mark (150x150)
│   └── icons.svg              # icon sprite
├── screenshots/               # Current production UI as reference (uid2 account)
│   ├── 01-login.png           #   public page, 3D grid background
│   ├── 02-dashboard.png       #   KPI row + charts + globe
│   ├── 03-email-inbox.png     #   table-first list
│   ├── 04-active-scans.png    #   live queue + completed list
│   ├── 05-scan-results.png    #   verdicts list
│   ├── 06-alerts.png          #   alert feed
│   ├── 07-campaigns.png       #   campaigns
│   └── 08-url-analysis.png    #   URL tool
└── code/
    └── frontend-source.zip    # frontend/src + public + package.json + vite config (177 KB)
                               # for Stitch's "add code" option — React 19 + Vite + Tailwind v4
```

## Fonts

The design uses **Inter** (UI) and **JetBrains Mono** (scores/IDs) — both
Google Fonts, already named in DESIGN.md typography tokens and selectable
by name in Stitch's font picker. No font files needed.

## Regenerating this bundle

- Screenshots: `/tmp/opencode/shots/bundle_capture.py` (Playwright, 1440x900)
- DESIGN.md lint: `npx @google/design.md lint stitch/DESIGN.md`
- Code zip: `src`, `public`, `package.json`, `vite.config.ts` zipped from `frontend/`
