---
version: 1
slug: "cmd-mcp-gateway-ui-layout-html"
primary_target: "internal/front/gatteweb/ui/layout.html"
related_targets: ["internal/front/gatteweb/ui/app.css","internal/front/gatteweb/ui/overview.html","internal/front/gatteweb/ui/tools.html","internal/front/gatteweb/ui/tool.html"]
---

# Surface: Gatte operator console (`mcp-gateway ui`)

Mode: Operate. A few operators take turns; routine tool approvals, rare incident actions. Constraints: no JavaScript, CSP `default-src 'none'; style-src 'self'`, one embedded stylesheet, system faces only, light and dark from prefers-color-scheme, blue and black shades only. Owner took the category standard: Apple-style simplicity, App Store Connect as the bar.

## Direction contract

THESIS: A calm Apple-grade console: the task first, the machinery out of sight until asked for. Refuses the metaphor-heavy, text-heavy console the first build became.

OWN-WORLD: Apple system faces; light ground #f5f5f7 with white grouped surfaces, dark ground black with #1c1c1e surfaces; one accent, system blue, for actions and links; hairline separators; 12px rounded groups, pill primary buttons; small authored SVG glyphs (chevron, check, warning). Danger is a solid dark badge with a warning glyph.

STORY: The operator sees what needs attention, opens it, reads the description and what changed, and approves this exact version.

FIRST VIEWPORT: Top bar with wordmark and plain-text navigation; large page title; a "Needs attention" grouped list with one row per changed tool, pending tool and unsigned backend, each with a chevron to act; then recent refusals.

FORM: Category standard (canon), App Store Connect as reference; seed key 1c240ecb.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
