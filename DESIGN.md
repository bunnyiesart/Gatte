---
name: Gatte operator console
description: A signal box for an MCP gateway; one lever, one fingerprint, pulled on purpose.
colors:
  ground: "#07090c"
  iron: "#0f131a"
  iron-2: "#161b24"
  rule: "#252d3a"
  rule-strong: "#3a4558"
  plate: "#e2e9f3"
  steel: "#98a6ba"
  dim: "#7a889e"
  signal: "#4d88ff"
  signal-hover: "#6d9dff"
  signal-ink: "#050d1f"
  signal-text: "#8db4ff"
  board: "#0a1730"
  board-2: "#0f2142"
  board-line: "#27437a"
  board-ink: "#d5e2f7"
  board-dim: "#7f93b8"
  board-lit-ink: "#041026"
  shelf: "#030406"
  day-ground: "#eef1f6"
  day-iron: "#ffffff"
  day-iron-2: "#f3f5f9"
  day-rule: "#d2d9e4"
  day-rule-strong: "#aab5c6"
  day-plate: "#07090c"
  day-steel: "#465265"
  day-dim: "#5b6678"
  day-signal: "#1d4fc4"
  day-signal-hover: "#173f9e"
  day-signal-ink: "#ffffff"
  day-signal-text: "#1a47b0"
typography:
  display:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "1.625rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  headline:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 700
    lineHeight: 1.5
    letterSpacing: "0.14em"
  title:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 650
    lineHeight: 1.5
    letterSpacing: "0.01em"
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "tnum"
  label:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 700
    lineHeight: 1.5
    letterSpacing: "0.14em"
  nameplate:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif"
    fontSize: "13px"
    fontWeight: 800
    letterSpacing: "0.32em"
  mono:
    fontFamily: "ui-monospace, SF Mono, Cascadia Mono, Menlo, Consolas, monospace"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.6
rounded:
  plate: "2px"
  panel: "3px"
spacing:
  cell: "9px 14px"
  bench: "16px"
  gutter: "32px"
  gutter-narrow: "16px"
  section: "40px"
components:
  button:
    backgroundColor: "{colors.iron}"
    textColor: "{colors.plate}"
    rounded: "{rounded.panel}"
    padding: "7px 16px"
    height: "36px"
  button-active:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.ground}"
  button-go:
    backgroundColor: "{colors.signal}"
    textColor: "{colors.signal-ink}"
    rounded: "{rounded.panel}"
    padding: "7px 16px"
    height: "36px"
  button-go-hover:
    backgroundColor: "{colors.signal-hover}"
    textColor: "{colors.signal-ink}"
  button-stop:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.ground}"
    rounded: "{rounded.panel}"
    padding: "7px 16px"
    height: "36px"
  button-stop-hover:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.plate}"
  tab:
    backgroundColor: "{colors.shelf}"
    textColor: "{colors.steel}"
    rounded: "{rounded.panel}"
    padding: "5px 11px 4px"
  tab-current:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.shelf}"
  input:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.plate}"
    rounded: "{rounded.panel}"
    padding: "6px 10px"
    height: "36px"
  state-plate:
    textColor: "{colors.steel}"
    typography: "{typography.label}"
    rounded: "{rounded.plate}"
    padding: "1px 8px"
  state-plate-danger:
    backgroundColor: "{colors.plate}"
    textColor: "{colors.ground}"
  lever-mark:
    backgroundColor: "{colors.board}"
    textColor: "{colors.board-dim}"
    typography: "{typography.mono}"
    rounded: "{rounded.panel}"
    padding: "4px 10px 4px 4px"
  lever-mark-lit:
    backgroundColor: "{colors.board-ink}"
    textColor: "{colors.board-lit-ink}"
  diagram-board:
    backgroundColor: "{colors.board}"
    textColor: "{colors.board-ink}"
    rounded: "{rounded.panel}"
    padding: "22px 24px 16px"
  register-table:
    backgroundColor: "{colors.iron}"
    textColor: "{colors.plate}"
    rounded: "{rounded.panel}"
    padding: "{spacing.cell}"
---

# Design System: Gatte operator console

## Overview

**Creative North Star: "The Signal Box"**

The console is a railway signal box: a black enamel lever frame, iron panels, a navy illuminated diagram board, enamelled plates with tracked capital lettering. Its doctrine is interlocking. A lever cannot be pulled unless the route shown is the route locked, and a tool cannot be approved unless the fingerprint shown is the one advertised. Every surface serves that one act: see what is locked, read the definition as a model will, pull exactly one lever for exactly one fingerprint.

It is dense and ruled, not airy. Tables are the train register book: ruled ledger lines and tabular numerals throughout. Colour is almost absent; the palette is blue and black shades only, and the only chromatic blue that carries meaning is signal blue, which means "you can act." Danger is never a new hue: it is inversion, a heavier frame, and the diagonal hatch of a lever collar. The world refuses the KPI-card admin dashboard: no metric tiles, no badges in colour, no shadows lifting cards off a page.

The system runs under hard constraints that are part of its character: server-rendered HTML with no JavaScript, one embedded stylesheet, Content-Security-Policy `default-src 'none'; style-src 'self'` (so no external fonts or assets, no inline styles), and light and dark themes from `prefers-color-scheme` alone.

**Key Characteristics:**
- Blue and black shades only; signal blue reserved for action.
- One strict state grammar drawn in enamel, outline, dash, hatch and inversion; never in hue.
- A night-navy diagram board that keeps its night in both themes.
- Tracked uppercase lettering for plates, tabs, headings and column heads; mono only for machine strings.
- A single authored motion: the lever throw.

## Colors

A near-black iron frame with cold blue-grey steel lettering, one navy board, and a single signal blue.

### Primary
- **Signal Blue** (`signal`; day `day-signal`): the only colour that means "you can act". Primary buttons, link text (`signal-text`), focus rings, the text caret and the selection highlight. Hover lightens in the dark theme and deepens in the light theme (`signal-hover`). Ink on a signal fill is `signal-ink`.

### Secondary
- **Night Board Navy** (`board`, `board-2`, `board-line`): the illuminated diagram's field, its section dividers and its rails. Identical in both themes.
- **Board Lamp** (`board-ink`, with `board-lit-ink` as the ink on a lit lamp; `board-dim` for unlit marks and notes): lettering and lit marks on the board. The board is not signal blue; it describes routes, it does not invite action.

### Neutral
- **Frame Black** (`ground`; day `day-ground`): page ground and input fields.
- **Iron** (`iron`, `iron-2`; day `day-iron`, `day-iron-2`): panels, tables, benches; `iron-2` for column heads, row hover and collared rows.
- **Ledger Rule** (`rule`, `rule-strong`): every hairline, table border and the double rules of the caption plate.
- **Enamel** (`plate`; day `day-plate`): primary lettering and every enamel fill in the state grammar. In the light theme enamel becomes black, so inversion still reads.
- **Steel** (`steel`) and **Dimmed Steel** (`dim`): secondary lettering, labels, disabled and unlit things.
- **Block Shelf Black** (`shelf`): the header strip, black in both themes; its lettering reuses the dark enamel and steel values.

### Named Rules
**The Signal Rule.** Signal blue is for actions only: `.go` buttons, links, focus, caret, selection. No state, count, badge or alarm is ever blue. If it is blue and pressing it does nothing, it is wrong.

**The Blue-and-Black Rule.** Brand commitment: every colour is a blue or a black shade. There is no red, amber or green, including for danger, errors or success.

**The Night Board Rule.** The diagram board keeps its navy night in the light theme too. Only the frame and panels change with the scheme.

## Typography

**Display Font:** system-ui (with -apple-system, Segoe UI, Roboto, Helvetica Neue, sans-serif)
**Body Font:** the same system sans stack
**Label/Mono Font:** ui-monospace (with SF Mono, Cascadia Mono, Menlo, Consolas, monospace)

**Character:** Plain system sans set like enamel plate lettering, tracked wide and capitalised for anything that names a place or a column; a system mono for the strings a machine wrote. System stacks are a hard constraint (light host, CSP forbids external fonts), and the lettering, not the face, carries the voice.

### Hierarchy
- **Display** (700, 1.625rem, 1.2, -0.01em, balanced wrap): the one page title.
- **Headline** (700, 0.8125rem, 0.14em tracking, uppercase, steel): section headings inside a page, 40px above.
- **Title** (650, 0.875rem): the caption plate's imperative sentence and button text (600, 0.02em).
- **Body** (400, 15px, 1.5, tabular numerals everywhere): prose; lead paragraphs hold to 70ch.
- **Label** (700, 0.6875rem, 0.14em, uppercase, steel): table column heads, fact terms, state plates (0.1em). Form labels sit at 0.75rem, 0.08em; tabs at 12px, 650, 0.12em.
- **Nameplate** (800, 13px, 0.32em, uppercase): the wordmark on its enamel plate, once per page.
- **Mono** (400, 0.8125rem, 1.6): identifiers, tool names, hashes, timestamps, command output.

### Named Rules
**The Machine String Rule.** Mono is only for what a machine wrote or will read: identifiers, hashes, timestamps and command output. Human prose, labels and buttons stay in the sans, even inside a mono block (`.measure > *` resets to sans).

**The Fingerprint Measure Rule.** Definitions, their alert and their facts share one fixed measure: one fingerprint line in mono, `calc(96ch + 42px)`, exactly "  observed fingerprint sha256:" plus 64 hex. Never wider, never fluid.

## Layout

A single centred column, `max-width: 1180px`, with 32px gutters (16px under 760px). The first view of the overview is the block shelf (nameplate plus plate-tabs, flex, wrapping), the page title and its caption plate, then the diagram board full width with its status line docked beneath it, then the register.

The diagram is a grid per backend: a track label column of `minmax(150px, 220px)` and a flexible row of lever marks on a 2px rail; it collapses to one column on narrow screens. The status line is one row of flexible count cells separated by hairlines, wrapping to two per row on phones.

Rhythm is ruled rather than spaced: table cells at 9px by 14px, benches at 16px padding with 14px gaps, section headings 40px above and 12px below, the caption plate 12px above and 22px below. Under 760px every table becomes a stack of register entries, each cell prefixed by its column name in label type (92px label column), and bench buttons go full width.

## Elevation & Depth

The system is flat. There are no drop shadows. Depth is tonal (ground, iron, iron-2) and ruled (hairline borders, double rules). The only `box-shadow` in the build is an inset 2px enamel frame on an alarm cell in the status line, which is a border, not a lift.

### Named Rules
**The Ruled, Not Lifted Rule.** Separation comes from rules and tone. Nothing floats; a panel is iron on frame black with a hairline.

## Shapes

Nearly square corners: 3px on panels, buttons, inputs, tabs, the board and focus rings; 2px on plates, state plates and lever numbers; 1px on collar sleeves. Borders are 1px hairlines at rest; 2px marks the heavy frame of a locked lever or alarm. The caption plate uses 3px double rules top and bottom. The recurring geometry is the lever: a 6px by 24px bar with a 12px handle, pivoting from its foot, and the collar: a hatched sleeve (`repeating-linear-gradient` at 135deg) clamped across it. The same hatch reappears as the collar band atop an alert and as the chip beside an alarm count.

## Components

### State Grammar
One grammar, applied wherever a thing has a state:
- **Served**: enamel-white fill (a lit lamp on the board; a thrown lever in the frame).
- **Approved / allowed**: enamel outline.
- **Pending**: dashed outline.
- **Danger** (locked/changed, alarms): enamel frame plus a hatched collar sleeve.
- **Pressed / current**: inversion (enamel fill, ground ink).
- **Disabled / dim**: dimmed steel.

**The One Grammar Rule.** State is drawn with fill, outline, dash, hatch and inversion only, never with a new colour and never with signal blue.

### Buttons
- **Shape:** squarish (3px), 36px minimum height; 30px inside table cells.
- **Primary (go):** signal blue fill and border, signal ink, 7px by 16px, 600 at 0.875rem. It names what it pins ("Approve sha256:..."), and sits after the diff it approves.
- **Hover / Focus:** 150ms ease-out colour changes; go lightens (or deepens, in daylight); focus is a 2px signal ring offset 2px. Pressing any button inverts it to enamel.
- **Default:** iron fill, strong rule border, enamel text; hover brings the border to enamel.
- **Stop:** enamel fill with ground ink (Block, Revoke); hover inverts back to ground.

### Chips (state plates)
- **Style:** 2px corners, 1px strong-rule outline, steel label type, uppercase.
- **State:** approved/allowed take an enamel outline; pending a dashed outline; changed, denied, failed and refused take the danger mark: a 2px enamel frame and a hatched collar sleeve before the word, the same sleeve locked levers and status-line alarms carry. Error blocks carry the collar strip along their top edge.

### Cards / Containers
- **Corner Style:** 3px.
- **Background:** iron on frame black; the board in navy.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px rule.
- **Internal Padding:** 16px (bench), 18px by 20px (definition), 22px by 24px (board).

### Inputs / Fields
- **Style:** frame-black field, 1px strong rule, 3px corners, 36px high, 240px minimum width; labels stacked above in uppercase label type with a sentence-case hint in dimmed steel.
- **Focus:** border and ring go signal blue; the caret is signal blue.
- **Mono fields:** for heads and hashes only.

### Navigation
- **Style:** the block shelf, always black. The nameplate is a framed enamel plate that takes signal blue on hover (it is a link). Tabs are outlined plates in tracked uppercase, steel at rest, enamel on hover.
- **Current:** inverted (enamel fill, shelf ink), never signal blue, because where you are is a state, not an action.
- **Mobile:** tabs wrap under the nameplate; gutters tighten to 16px.

### Caption Plate
The page's single imperative, lettered between two 3px double rules, no box and no fill, so it never reads as a control. One per page, directly under the title.

### Diagram Board and Lever Marks
The navy board lays out one track section per backend, each tool a numbered lever mark on the rail. Unlit marks are board-dim outlines; served marks are lit enamel lamps; locked marks carry a 2px lamp frame, bold lettering and a hatched chip. An unsigned backend's rail is dashed. A legend closes the board.

### Lever Frame
The tools register draws a lever per row. Normal levers stand in dimmed steel; served levers are enamel and thrown back (-22deg); locked levers are enamel with a hatched collar. **The one authored motion:** hovering a row takes the lever's weight, a 220ms ease-out throw (`cubic-bezier(0.16, 1, 0.3, 1)`), smaller for a collared lever. Reduced motion turns it off, with every transition.

### Collar Alert
An iron panel with a 1px enamel frame and an 8px hatched band across its top; bold statement, steel explanation. Used for a locked definition.

### Hidden Code Point Mark
A hidden code point is an inverted enamel slug with a 1px outline offset, set inline in the definition, so an invisible character becomes a physical thing on the page.

### Status Line
Counts docked under the board: bold enamel numeral, steel noun, hairline separators. An alarm cell takes an inset enamel frame and the hatched chip.

## Do's and Don'ts

### Do:
- **Do** reserve signal blue for buttons that act, links, focus, caret and selection.
- **Do** draw every state with the one grammar: fill (served), outline (approved), dash (pending), frame plus hatch (danger), inversion (pressed/current), dimmed steel (disabled).
- **Do** set definitions and their alerts on the fixed fingerprint measure, `calc(96ch + 42px)`.
- **Do** use mono only for identifiers, hashes, timestamps and command output, and tabular numerals everywhere.
- **Do** keep the diagram board night-navy in both themes, and theme everything else through `prefers-color-scheme`.
- **Do** put one imperative per page on a caption plate between double rules.
- **Do** use lab names (casemgmt, logsearch, docsearch, threatintel) and RFC 5737/2606 stand-ins in every example.

### Don't:
- **Don't** introduce any hue outside blue and black shades; no red, amber or green for danger or success.
- **Don't** colour a state, count or alarm signal blue.
- **Don't** box the caption plate or give it a fill; it must never read as a control.
- **Don't** mark the current tab with signal blue; inversion only.
- **Don't** add drop shadows or lifted cards; rules and tone carry depth.
- **Don't** add JavaScript, inline styles, external fonts or assets, or a second stylesheet.
- **Don't** author any motion other than the lever throw, and never without a reduced-motion off switch.
- **Don't** build KPI cards or metric tiles; counts live in the status line and the register.
