Revamp the existing Phishing-Guard 2.0 production web app (an AI email
phishing detection platform) — modernize its visual design while
preserving its identity and complete information architecture.

Non-negotiable constraints:
- Keep the dark security-console (SOC) identity and the electric-blue
  primary with red/amber/green verdict colors defined in DESIGN.md.
- Keep every page and feature: Login, Dashboard, Email Inbox, Active
  Scans, Scan Results (+ detail + report), Alerts, Campaigns,
  Attribution Graph, URL Analysis, Attachments, Email Trace, Settings,
  Users (admin), System Health (admin).
- Layout shell stays: fixed ~230px left sidebar with grouped nav
  (MONITOR / ANALYZE / admin), top app bar with primary action button,
  scrollable main region, KPI-card row on Dashboard, table-first
  density on list pages.
- Desktop-first at 1440x900; responsive down to laptop widths.

Design direction for the revamp:
- Refresh surfaces, spacing rhythm, iconography and chart styling so
  the product looks like a modern 2026 security product (e.g. Linear,
  Vercel, Datadog polish) — sharper hierarchy, more breathing room,
  consistent 4/8px spacing grid, refined glows used only for live or
  threat states.
- Improve scannability of verdicts: DANGEROUS / SUSPICIOUS / SAFE
  badges and scores must remain instantly readable.
- Data-dense tables stay tables (no card-per-row on desktop).

Generate one screen per page listed above, desktop 1440px wide, using
the tokens in the attached DESIGN.md.
