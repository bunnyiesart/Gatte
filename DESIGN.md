---
name: Gatte operator console
description: A calm Apple-grade console for an MCP gateway; the task first, the machinery out of sight until asked for.
colors:
  ground: "#f5f5f7"
  surface: "#ffffff"
  surface-raised: "#fafafc"
  fill: "rgba(118, 118, 128, 0.12)"
  fill-strong: "rgba(118, 118, 128, 0.2)"
  ink: "#1d1d1f"
  ink-secondary: "#6e6e73"
  ink-tertiary: "#66666b"
  separator: "rgba(60, 60, 67, 0.16)"
  accent: "#0071e3"
  accent-hover: "#0077ed"
  accent-press: "#006edb"
  accent-text: "#0062c4"
  accent-soft: "rgba(0, 113, 227, 0.1)"
  on-accent: "#ffffff"
  btn: "#0071e3"
  btn-hover: "#0066cc"
  btn-press: "#005bb5"
  danger-fill: "#1d1d1f"
  danger-ink: "#ffffff"
  mark-fill: "#1d1d1f"
  mark-ink: "#ffffff"
  diff-add: "rgba(0, 113, 227, 0.1)"
  bar: "rgba(255, 255, 255, 0.78)"
  ground-dark: "#000000"
  surface-dark: "#1c1c1e"
  surface-raised-dark: "#232325"
  fill-dark: "rgba(118, 118, 128, 0.24)"
  fill-strong-dark: "rgba(118, 118, 128, 0.36)"
  ink-dark: "#f5f5f7"
  ink-secondary-dark: "#a1a1a6"
  ink-tertiary-dark: "#9e9ea4"
  separator-dark: "rgba(84, 84, 88, 0.6)"
  accent-dark: "#0a84ff"
  accent-hover-dark: "#409cff"
  accent-press-dark: "#0071e3"
  accent-text-dark: "#5aabff"
  accent-soft-dark: "rgba(10, 132, 255, 0.18)"
  on-accent-dark: "#ffffff"
  btn-dark: "#0071e3"
  btn-hover-dark: "#0066cc"
  btn-press-dark: "#005bb5"
  danger-fill-dark: "#f5f5f7"
  danger-ink-dark: "#000000"
  mark-fill-dark: "#f5f5f7"
  mark-ink-dark: "#000000"
  diff-add-dark: "rgba(10, 132, 255, 0.2)"
  bar-dark: "rgba(22, 22, 23, 0.78)"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, SF Pro Display, Helvetica Neue, Segoe UI, Roboto, sans-serif"
    fontSize: "32px"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "-0.025em"
  display-mono:
    fontFamily: "ui-monospace, SF Mono, Menlo, Cascadia Mono, Consolas, monospace"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, SF Pro Display, Helvetica Neue, Segoe UI, Roboto, sans-serif"
    fontSize: "20px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  wordmark:
    fontFamily: "-apple-system, BlinkMacSystemFont, SF Pro Display, Helvetica Neue, Segoe UI, Roboto, sans-serif"
    fontSize: "19px"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "-0.02em"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, SF Pro Text, Helvetica Neue, Segoe UI, Roboto, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.47
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
  prose:
    fontFamily: "-apple-system, BlinkMacSystemFont, SF Pro Text, Helvetica Neue, Segoe UI, Roboto, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.55
  caption:
    fontFamily: "-apple-system, BlinkMacSystemFont, SF Pro Text, Helvetica Neue, Segoe UI, Roboto, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.47
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, SF Pro Text, Helvetica Neue, Segoe UI, Roboto, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    letterSpacing: "0"
  code:
    fontFamily: "ui-monospace, SF Mono, Menlo, Cascadia Mono, Consolas, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "0"
rounded:
  code: "5px"
  segment: "7px"
  control: "8px"
  segmented: "9px"
  group: "12px"
  pill: "999px"
  circle: "50%"
spacing:
  hair: "2px"
  xs: "6px"
  sm: "10px"
  row-y: "14px"
  row-x: "18px"
  gutter-phone: "16px"
  gutter: "24px"
  head: "28px"
  section: "40px"
  page-end: "80px"
components:
  button-primary:
    backgroundColor: "{colors.btn}"
    textColor: "{colors.on-accent}"
    typography: "{typography.body}"
    rounded: "{rounded.pill}"
    padding: "8px 18px"
    height: "36px"
  button-primary-hover:
    backgroundColor: "{colors.btn-hover}"
  button-primary-active:
    backgroundColor: "{colors.btn-press}"
  button-secondary:
    backgroundColor: "{colors.fill}"
    textColor: "{colors.accent-text}"
    rounded: "{rounded.pill}"
    padding: "8px 18px"
    height: "36px"
  button-secondary-hover:
    backgroundColor: "{colors.fill-strong}"
  button-destructive:
    backgroundColor: "{colors.danger-fill}"
    textColor: "{colors.danger-ink}"
    rounded: "{rounded.pill}"
    padding: "8px 18px"
    height: "36px"
  button-small:
    rounded: "{rounded.pill}"
    padding: "5px 14px"
    height: "30px"
  badge-approved:
    backgroundColor: "{colors.accent-soft}"
    textColor: "{colors.accent-text}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "3px 10px 3px 8px"
  badge-danger:
    backgroundColor: "{colors.danger-fill}"
    textColor: "{colors.danger-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "3px 10px 3px 8px"
  badge-pending:
    backgroundColor: "{colors.fill}"
    textColor: "{colors.ink-secondary}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "3px 10px 3px 8px"
  group:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.group}"
  list-row:
    textColor: "{colors.ink}"
    padding: "14px 18px"
  list-row-hover:
    backgroundColor: "{colors.surface-raised}"
  lead-icon:
    backgroundColor: "{colors.fill}"
    textColor: "{colors.ink-secondary}"
    rounded: "{rounded.control}"
    size: "32px"
  input:
    backgroundColor: "{colors.fill}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
    height: "36px"
  input-focus:
    backgroundColor: "{colors.surface}"
  segmented-control:
    backgroundColor: "{colors.fill}"
    rounded: "{rounded.segmented}"
    padding: "2px"
  segmented-item-selected:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.segment}"
    padding: "5px 14px"
  nav-item:
    textColor: "{colors.ink-secondary}"
    rounded: "{rounded.control}"
    padding: "6px 12px"
  nav-item-current:
    backgroundColor: "{colors.fill}"
    textColor: "{colors.ink}"
  top-bar:
    backgroundColor: "{colors.bar}"
    height: "52px"
  notice-danger:
    backgroundColor: "{colors.danger-fill}"
    textColor: "{colors.danger-ink}"
    rounded: "{rounded.group}"
    padding: "14px 18px"
  hidden-mark:
    backgroundColor: "{colors.mark-fill}"
    textColor: "{colors.mark-ink}"
    rounded: "{rounded.code}"
    padding: "1px 5px"
---

# Design System: Gatte operator console

## Overview

**Creative North Star: "The Settings Pane, Done Carefully"**

The console is the Apple category standard with App Store Connect as the bar: the familiar grouped-list idiom, executed at full craft rather than reinvented. An operator lands on a large page title, a "Needs attention" group with one row per item, and a chevron to act. Everything technical (schemas, fingerprints, command output) waits behind a disclosure until asked for. There is no metaphor to learn; the interface is the settings pane an operator already knows.

Density is calm, not sparse: 15px body text, 14px by 18px rows, 40px between sections, a 1080px column. Color is almost entirely neutral grey and white (or black and near-black in dark mode), with one system blue reserved for actions, links and the "approved" state. Danger is never red: the brand is blue and black, so a changed tool, an unsigned backend, a refusal or a destructive action is a solid near-black fill in light mode and an inverted near-white fill in dark mode. Maximum contrast carries the alarm that hue would carry elsewhere.

The page runs under `default-src 'none'; style-src 'self'`: one stylesheet, system faces, no JavaScript, no images. Every glyph is a small authored inline SVG; every interaction is a link, a form post or a native `<details>`. Light and dark follow `prefers-color-scheme` with no toggle.

**Key Characteristics:**
- Apple system faces (SF via `-apple-system`), display cut for titles, text cut for body.
- White grouped surfaces on a light grey ground; `#1c1c1e` groups on black in dark mode.
- Hairline separators between rows, never boxes around them.
- One accent, system blue, for actions, links and the approved state.
- Danger as a solid near-black (light) or near-white (dark) fill, never red.
- Pill buttons, segmented control for filters, disclosures for anything technical.
- Frosted sticky bar on desktop; list rows on phones.

## Colors

A neutral Apple grey scale with a single system blue; the only "loud" value is the inverted danger fill.

### Primary
- **System Blue** (`accent`, `accent-dark`): caret and focus-ring source. Link text and the `row-action` label ("Review", "View") use `accent-text`, which holds 4.5:1 on the grey page ground as well as on white. Hover and press steps (`accent-hover`, `accent-press`) exist for tinted states.
- **Button Blue** (`btn`, `btn-hover`, `btn-press`): the fill of primary buttons, identical in light and dark so white label contrast stays fixed (4.7:1 at rest, 5.6:1 on hover).
- **Blue Ink on Tint** (`accent-text`, `accent-text-dark`): the text and glyph color for anything blue that sits on a tinted fill: secondary buttons, approved badges, approved lead icons and the success result icon. It is a step darker (light) or lighter (dark) than System Blue so it clears AA on `accent-soft` and `fill` (about 5.2:1 light, 5.7:1 dark).
- **Blue Wash** (`accent-soft`, `accent-soft-dark`): approved badge and icon fill, text selection, input focus halo. `diff-add` is the same wash for added lines in a diff.

### Neutral
- **Canvas Grey / Black** (`ground`, `ground-dark`): page ground.
- **Group White / Graphite** (`surface`, `surface-dark`): grouped lists, tables, prose, forms, notices, the selected segment.
- **Row Hover** (`surface-raised`, `surface-raised-dark`): hover state of linked rows, table rows and disclosure summaries.
- **Control Fill** (`fill`, `fill-strong` and dark variants): translucent grey for inputs, secondary buttons, pending badges, nav current state, the segmented track, inline code and neutral lead icons. `fill-strong` is the secondary button hover and the pressed-row state.
- **Ink** (`ink`), **Secondary Ink** (`ink-secondary`), **Tertiary Ink** (`ink-tertiary`): titles and body; subtitles, column heads and field labels; chevrons, placeholders, row sub-lines and struck diff lines.
- **Hairline** (`separator`, `separator-dark`): 1px row, table and bar separators; notice outline.
- **Frosted Bar** (`bar`, `bar-dark`): translucent top-bar fill under the blur.

### Danger (inverted neutral)
- **Alarm Fill** (`danger-fill`/`danger-ink`, dark `danger-fill-dark`/`danger-ink-dark`): changed-tool and unsigned-backend lead icons, danger badges, the danger notice, destructive buttons, the failed result icon. `mark-fill`/`mark-ink` use the same pair for highlighted hidden characters.

### Named Rules
**The One Blue Rule.** System blue means "you can act here" or "this is approved". It is never decoration, never a heading color, never a background panel.

**The Black Alarm Rule.** Danger is the ink color turned into a fill: near-black in light, near-white in dark, always with the warning glyph. Red, orange and yellow do not exist in this system.

**The Tint Needs Deeper Ink Rule.** Blue text on any tinted or grey fill uses `accent-text`, never `accent`. `accent` is for text sitting directly on a white or black surface.

## Typography

**Display Font:** SF Pro Display via `-apple-system` (with Helvetica Neue, Segoe UI, Roboto)
**Body Font:** SF Pro Text via `-apple-system` (same fallbacks)
**Label/Mono Font:** SF Mono via `ui-monospace` (with Menlo, Cascadia Mono, Consolas)

**Character:** The platform's own faces, tightened slightly (-0.01em body, -0.025em titles) the way Apple sets them. Mono appears wherever the text is an identifier a machine will match: tool names, subjects, fingerprints, schemas, diffs.

### Hierarchy
- **Display** (700, 32px, 1.12; 28px under 720px and on the result page): one per page, the page title, balanced wrapping.
- **Display Mono** (700, 28px mono): the page title when it is a tool name; wraps anywhere.
- **Headline** (600, 20px, 1.2): section titles above a group.
- **Wordmark** (600, 19px): "Gatte" in the bar; there is no logo.
- **Body** (400, 15px, 1.47, tabular numerals throughout): rows, cells, buttons, inputs. Page subtitles step up to 16px in secondary ink.
- **Prose** (400, 16px, 1.55, 72ch max): tool descriptions, the one place people read paragraphs.
- **Caption** (13px secondary ink, 60ch max): the sentence under an action that says exactly what it does.
- **Label** (600, 12px, no tracking, sentence case): table column heads, badges, fact labels.
- **Code** (400, 13px, 1.6 mono; diffs at 1.7): schemas, command output, diffs.

### Named Rules
**The Sentence Case Rule.** Labels, badges, column heads and buttons are sentence case at normal tracking. Nothing in the console is uppercase or letter-spaced.

**The Machine Text Is Mono Rule.** If a value is an identifier the gateway matches on, it is set in mono; human descriptions never are.

## Layout

A single centered column (1080px max) with 24px gutters, 40px top padding and 80px at the end. The page head (title plus subtitle) is followed by 28px; sections are separated by 40px, each a 20px headline 10px above its group. Groups stack at 10px in disclosure stacks. Rows pad 14px by 18px; table cells 12px by 18px.

At 720px and below: gutters drop to 16px, the title to 28px, and the bar stops being sticky. The wordmark wraps above the nav, and the six nav items share one full-width row at 13px with space-between distribution, no scrolling. Tables with a `list` role become list rows: a three-area grid (title, subtitle, second subtitle) with the badge and chevron on the right, secondary columns hidden. Other tables become labelled stacks, with an 84px label column taken from each cell's label. Form submit buttons go full width.

## Elevation & Depth

Depth is tonal first: white on grey in light mode, graphite on black in dark. In light mode, groups carry a barely-there ambient shadow to lift them off the ground; in dark mode shadows are removed and the tonal step does the work. The top bar is the only layer that floats, and it floats by translucency and blur, not shadow.

### Shadow Vocabulary
- **Group lift** (`box-shadow: 0 1px 2px rgba(0,0,0,0.04), 0 4px 16px rgba(0,0,0,0.04)`): every grouped surface, light mode only.
- **Selected segment** (`box-shadow: 0 1px 3px rgba(0,0,0,0.12)`): the current segment of a segmented control.
- **Notice hairline** (`box-shadow: inset 0 0 0 1px` separator): neutral and error notices, which sit on the ground without a group.
- **Frosted bar** (`backdrop-filter: saturate(180%) blur(20px)` over `bar`, 1px bottom hairline): desktop top bar.

### Named Rules
**The Dark Is Flat Rule.** No shadows in dark mode; surfaces separate by tone alone.

## Shapes

Continuous, gently rounded forms. Groups and notices are 12px; controls that sit inside them (inputs, nav items, lead icons) are 8px; the segmented track is 9px around 7px segments; inline code and hidden-character marks are 5px. Every button and badge is a full pill (999px). Result icons are circles. Borders are avoided: rows divide with 1px hairlines, inputs have a transparent border that turns blue only on focus.

Glyphs are small authored inline SVGs on a 16px box with a 1.5 to 1.6 stroke and round caps: chevron (8 by 14), check-in-circle, warning triangle, and a dashed circle for pending. Badges shrink them to 13px; result icons scale them to 28px inside a 56px circle.

## Components

### Buttons
Quiet pills that read as Apple controls.
- **Shape:** full pill (999px), 36px minimum height, 8px by 18px padding, 500 weight at 15px.
- **Primary:** Button Blue fill with white label; hover and press step darker. One per view, on the action the page exists for ("Approve this version", "Done").
- **Secondary:** grey control fill with Blue Ink on Tint label; hover to `fill-strong`.
- **Destructive:** Alarm Fill pill (Revoke approval, Block); hover drops opacity to 0.86.
- **Small:** 30px, 5px by 14px, 13px, for in-row actions such as Unblock.
- **Press:** every button scales to 0.98 over 100ms. Backgrounds transition over 150ms ease-out.
- When a tool contains hidden characters, "Approve this version" deliberately loses its primary fill and renders as secondary.

### Badges
- **Style:** pill, 12px 600 label, 13px leading glyph, 3px by 10px (8px on the glyph side).
- **Approved / signed:** Blue Wash with Blue Ink on Tint and the check glyph.
- **Pending:** Control Fill with secondary ink and the dashed-circle glyph.
- **Changed / unsigned / denied / failed:** Alarm Fill with the warning glyph.

### Grouped lists and tables
- **Corner Style:** 12px, content clipped.
- **Background:** Group White / Graphite; group lift in light mode only.
- **Rows:** 14px by 18px, 1px hairline between rows. A linked row is a 32px lead icon (8px radius, neutral fill, Alarm Fill for changed or unsigned, Blue Wash for ok), a title (600) with a 14px secondary detail line, an optional blue action word, and a tertiary chevron. Hover to Row Hover; press to Control Fill.
- **Tables:** 12px 600 secondary column heads over a hairline, 12px by 18px cells, whole row clickable through its first link, hover to Row Hover. Numbers right-aligned and tabular.
- **Empty state:** inside the group, a bold one-line sentence and a plain follow-up, optionally with an ok lead icon.

### Segmented control
- **Style:** 2px-padded grey track (9px), 13px 500 segments (7px) each carrying a secondary-ink count.
- **State:** the current segment is white (graphite in dark) with the selected-segment shadow; others hover to Control Fill. Filters are links, not scripts.

### Inputs / Fields
- **Style:** 36px, 7px by 12px, 8px radius, Control Fill, no visible border, 15px text; mono variant at 14px. Labels are 13px 500 secondary ink stacked 6px above.
- **Focus:** fill turns to surface, border turns System Blue, 3px Blue Wash halo.
- Forms live inside a group with 18px padding and 16px gaps, wrapping fields at 220px minimum.

### Navigation
- **Top bar:** 52px, wordmark left, plain-text nav 32px after it. Items are 14px secondary ink, 6px by 12px, 8px radius; hover and current both take Control Fill with primary ink, current also 600 weight. Sticky and frosted on desktop.
- **Phone:** non-sticky, nav on its own full-width row, 13px items at 5px by 6px, spaced between.
- **Back link:** blue text with a leading reversed chevron above the page head.

### Notices
- **Neutral / error:** surface fill, 12px radius, inset hairline, 14px by 18px, leading glyph; error output in 13px pre-wrapped mono.
- **Danger:** Alarm Fill, no outline, warning glyph, bold lead sentence.

### Disclosures
Every schema, fingerprint and command output sits in a `<details>` group: a 500-weight summary row with a trailing chevron that rotates 90 degrees over 200ms `cubic-bezier(0.2, 0.8, 0.2, 1)` when open, content padded 18px with 16px below. Facts inside are a grid of 12px secondary labels over 13px values.

### Tool review (signature)
The description is a prose group; a changed tool shows a mono diff group instead, where added lines take the `diff-add` wash, removed lines are tertiary and struck through, and gaps are tertiary. Hidden code points render as small inverted mono marks (Alarm Fill pair, 0.8em 600) so they cannot be missed. Actions stack below with a caption under each button stating exactly what it does.

### Result page
A centered stack: a 56px circular icon (Blue Wash with check for success, Alarm Fill with warning for failure), a 28px title, a summary line, a primary "Done" pill, then the command output in a 720px disclosure.

## Do's and Don'ts

### Do:
- **Do** take every color from the custom properties in `app.css`; light and dark swap only there, via `prefers-color-scheme`.
- **Do** use `accent-text` for blue text or glyphs on `accent-soft` or `fill`, and `btn` for primary button fills.
- **Do** express danger with the Alarm Fill pair and the warning glyph, and pending with Control Fill and the dashed circle.
- **Do** put new content in 12px white groups divided by 1px hairlines, with 14px by 18px rows.
- **Do** keep one primary pill per view, and a caption under each consequential action that says exactly what it does.
- **Do** hide schemas, fingerprints and command output behind `<details>` disclosures.
- **Do** draw any new glyph as an authored inline SVG on the 16px, 1.5-stroke, round-cap grid.
- **Do** give every data table phone behavior: list rows for lists, labelled stacks otherwise.

### Don't:
- **Don't** use red, orange, yellow or green for any state; the palette is blue and black shades.
- **Don't** add a second accent hue or use blue for decoration, headings or panels.
- **Don't** add JavaScript, inline styles, web fonts, images or icon fonts; the CSP forbids them.
- **Don't** set labels, badges or buttons in uppercase or with letter-spacing.
- **Don't** add shadows in dark mode or heavier shadows in light mode than the group lift.
- **Don't** put borders around rows or cards; separate with hairlines and tone.
- **Don't** use real deployment names, hosts or paths in examples; use casemgmt, logsearch, docsearch, threatintel and RFC 5737 / RFC 2606 stand-ins.
