---
version: alpha
name: Phishing-Guard SOC Console
description: Dark security-operations theme for Phishing-Guard 2.0, an AI email threat detection, geolocation and forensics dashboard.
colors:
  primary: "#3B82F6"
  primary-hover: "#2563EB"
  primary-glow: "rgba(59,130,246,0.15)"
  danger: "#EF4444"
  warning: "#F59E0B"
  safe: "#10B981"
  background: "#0A0C10"
  panel: "#0F1117"
  card: "#161B24"
  input: "#1C2333"
  border-subtle: "#1E2736"
  border-default: "#253044"
  border-emphasis: "#2D3B52"
  text-primary: "#F1F5F9"
  text-secondary: "#94A3B8"
  text-muted: "#4B5563"
  danger-subtle: "#2D1B1B"
  warning-subtle: "#2D2416"
  safe-subtle: "#1A2D24"
  on-primary: "#FFFFFF"
typography:
  body:
    fontFamily: Inter
    fontSize: 0.875rem
    fontWeight: 400
    lineHeight: 1.5
  h1:
    fontFamily: Inter
    fontSize: 1.5rem
    fontWeight: 600
    lineHeight: 1.25
  h2:
    fontFamily: Inter
    fontSize: 1.125rem
    fontWeight: 600
    lineHeight: 1.3
  kpi-number:
    fontFamily: Inter
    fontSize: 2.5rem
    fontWeight: 700
    lineHeight: 1
  label-caps:
    fontFamily: Inter
    fontSize: 0.7rem
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: 0.08em
  mono:
    fontFamily: JetBrains Mono
    fontSize: 0.875rem
    fontWeight: 500
rounded:
  sm: 4px
  md: 6px
  lg: 8px
  full: 9999px
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: 8px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.text-secondary}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: 8px
  input:
    backgroundColor: "{colors.input}"
    textColor: "{colors.text-primary}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: 8px
  card:
    backgroundColor: "{colors.card}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.lg}"
    padding: 16px
  badge-danger:
    backgroundColor: "{colors.danger-subtle}"
    textColor: "{colors.danger}"
    typography: "{typography.label-caps}"
    rounded: "{rounded.full}"
  badge-warning:
    backgroundColor: "{colors.warning-subtle}"
    textColor: "{colors.warning}"
    typography: "{typography.label-caps}"
    rounded: "{rounded.full}"
  badge-safe:
    backgroundColor: "{colors.safe-subtle}"
    textColor: "{colors.safe}"
    typography: "{typography.label-caps}"
    rounded: "{rounded.full}"
  sidebar:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text-primary}"
    padding: 16px
  nav-item-active:
    backgroundColor: "{colors.primary-glow}"
    textColor: "{colors.primary}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: 8px
  table-header:
    textColor: "{colors.text-muted}"
    typography: "{typography.label-caps}"
  divider:
    backgroundColor: "{colors.border-default}"
  row-separator:
    backgroundColor: "{colors.border-subtle}"
  focus-ring:
    backgroundColor: "{colors.border-emphasis}"
---

## Overview

Phishing-Guard 2.0 is a security operations console: a dense, data-first
dark UI for triaging phishing emails, watching live scans and reading
forensic reports. The feel is "SOC console" — near-black blue-tinted
canvas, slate panels separated by hairline borders, electric blue for
interaction, and glowing red/amber/green as the language of threat
verdicts. Information density and glanceable status beat decoration.

## Colors

Layered near-black surfaces with one interactive accent and three
strictly semantic status colors.

- **Primary (#3B82F6):** electric blue — every interactive element:
  buttons, links, focus rings, active nav, selected states. Hover
  darkens to #2563EB with a soft blue glow.
- **Danger (#EF4444) / Warning (#F59E0B) / Safe (#10B981):** reserved
  exclusively for verdicts and alert states — DANGEROUS, SUSPICIOUS,
  SAFE badges, KPI card borders, chart series, pulse animations.
  Never used decoratively.
- **Surfaces:** background #0A0C10 → panel #0F1117 → card #161B24 →
  input #1C2333, each step slightly lighter to build depth without
  shadows.
- **Borders:** #1E2736 subtle → #253044 default → #2D3B52 emphasis,
  1px hairlines everywhere.
- **Text:** #F1F5F9 primary, #94A3B8 secondary, #4B5563 muted;
  status text tints #FCA5A5 / #FCD34D / #6EE7B7.

## Typography

- **Inter** (300–700) for all UI text; body 14px, page titles 24px
  semibold, KPI numbers 40px bold.
- **Uppercase micro-labels:** 11px semibold, 0.08em letter-spacing for
  section headers, table headers, nav group titles (MONITOR, ANALYZE),
  KPI labels.
- **JetBrains Mono** (400–700) for machine data: scores, scan IDs,
  email numbers, hashes, domains, timestamps, code.

## Layout

Desktop-first application shell (designed at 1440x900):

- **Fixed left sidebar ~230px:** shield logo + wordmark "PHISHING-GUARD"
  with version chip on top; nav grouped under uppercase micro-labels —
  MONITOR (Dashboard, Email Inbox, Active Scans, Alerts), ANALYZE (Scan
  Results, Attribution Graph, Campaigns, URL Analysis, Attachments);
  admin group (System Health, Settings, Users) at the bottom for
  admin roles. Active item = blue glow background + left accent.
- **Top app bar:** breadcrumb + page title left; global actions right
  (primary "Fetch Emails" button, live clock, user avatar chip).
- **Main region:** single scrollable column, 24px page padding, cards
  arranged in responsive CSS-grid (KPI row of 4, then 2-column chart
  panels, then full-width data tables).
- **Full-page routes:** Login (centered card on a dark perspective-grid
  background), report/print view (light palette override).

## Elevation & Depth

Flat, hairline-bordered panels — no drop shadows. Depth comes from the
surface ladder (background → panel → card). The signature treatment is
colored glow: `0 0 16px` semantic glows at ~15% alpha for cards,
badges and buttons in danger/warning/safe/primary states, plus pulsing
glow keyframes on live/active threat indicators and a shimmer
skeleton-loading state.

## Shapes

Restrained geometry: 8px radius on cards and panels, 6px on buttons,
inputs and nav items, 4px on skeletons, full pill on score chips and
badges. 1px borders only. Scrollbars 6px wide, blue on hover.

## Components

- **KPI card:** uppercase label, huge number, small trend chip, icon
  top-right; border + glow tinted by severity (danger/warning/safe/primary).
- **Verdict badge:** pill with subtle tinted background, bright status
  text, uppercase label-caps, soft glow (score-danger/warning/safe).
- **Data table:** uppercase muted headers, 12px/16px cells, hairline
  row separators, hover row tint, clickable rows.
- **Sidebar nav item:** icon + 13px label, 6px radius; active state =
  primary-tinted background with glow; grouped under uppercase
  micro-labels.
- **Buttons:** filled primary (blue, glow on hover) and ghost (outline,
  tinted hover); 6px radius, inline icon support.
- **Inputs:** card-input surface, 6px radius, primary focus ring
  (2px glow), muted placeholder.
- **Status panel / empty state:** centered icon + 13px muted message
  inside a bordered panel.
- **Live indicator:** small bouncing dot (safe/warning/danger) with
  pulsing glow for running scans.
- **Toast:** dark panel, colored left accent, auto-dismiss.
- **Charts:** area/line with semantic series colors, donut breakdown
  with center total, tooltip on card surface; globe (threat origins)
  and force-graph (attribution) visualizations on dark panels.

## Do's and Don'ts

- DO keep the near-black blue-tinted background ladder; DON'T use pure
  black or large light areas (light palette only in print/export).
- DO reserve red/amber/green strictly for verdicts and threat states;
  DON'T use them for decoration or branding.
- DO render scores, IDs, hashes, domains and timestamps in JetBrains
  Mono.
- DO use uppercase 11px micro-labels for section headers and table
  columns.
- DO express emphasis with colored glow shadows; DON'T use heavy
  drop-shadows or glassmorphism blur.
- DO keep 1px hairline borders on every panel, table and input.
- DO maintain WCAG AA contrast for text (#94A3B8 minimum on #161B24).
- DON'T redesign the information architecture: the sidebar groups,
  KPI row, and table-first layout are fixed product constraints.
