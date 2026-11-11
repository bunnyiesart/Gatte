---
name: Gatte operator console
description: A classic system UI for an MCP gateway's operators; grey panels, bevelled edges, plain words.
colors:
  face: "#c0c0c0"
  ground: "#b4b4b4"
  field: "#ffffff"
  bevel-light: "#ffffff"
  bevel-dark: "#808080"
  edge: "#000000"
  ink: "#000000"
  ink-secondary: "#303030"
  ink-tertiary: "#484848"
  link: "#0000a8"
  title-bar: "#000080"
  on-title-bar: "#ffffff"
  select: "#000080"
  on-select: "#ffffff"
  ok: "#005c00"
  danger: "#800000"
  danger-text: "#800000"
  on-danger: "#ffffff"
  mark: "#000000"
  on-mark: "#ffff00"
  diff-add: "#d8e8d8"
  face-dark: "#3a3a3a"
  ground-dark: "#2c2c2c"
  field-dark: "#1e1e1e"
  bevel-light-dark: "#5c5c5c"
  bevel-dark-dark: "#161616"
  ink-dark: "#f0f0f0"
  ink-secondary-dark: "#d0d0d0"
  ink-tertiary-dark: "#b8b8b8"
  link-dark: "#a8c0ff"
  title-bar-dark: "#1c2c6c"
  select-dark: "#2c46a8"
  ok-dark: "#8fdc8f"
  danger-dark: "#b03030"
  danger-text-dark: "#ff9a9a"
  mark-dark: "#ffff00"
  on-mark-dark: "#000000"
  diff-add-dark: "#20402a"
typography:
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, Tahoma, Helvetica Neue, Arial, sans-serif"
    fontSize: "13px"
    lineHeight: 1.45
    fontFeature: "tnum"
  mono:
    fontFamily: "ui-monospace, Menlo, Consolas, Courier New, monospace"
  title:
    fontSize: "20px"
    fontWeight: 700
  headline:
    fontSize: "14px"
    fontWeight: 700
  caption:
    fontSize: "12px"
rounded:
  everything: "0"
---

# Design System: Gatte operator console

## Overview

The console looks like a 1990s desktop application (design/adr/0061 §1): grey
panels, 1px bevelled edges, the platform's plain system font and square
buttons. It is minimal on purpose. An operator should recognise every control
on sight: a raised button, a sunken text field, a white list view inside a
grey panel, a drop-down menu.

The page runs under `default-src 'none'; style-src 'self'`: one stylesheet
(`internal/front/gatteweb/ui/app.css`), system faces, no JavaScript, no
images. Every interaction is a link, a form post or a native `<details>`.
Light and dark follow `prefers-color-scheme` with no toggle.

**Key characteristics:**
- Grey face panels on a slightly darker grey ground.
- 1px bevels: raised is light top-left, dark bottom-right; sunken is the
  reverse.
- White sunken fields for inputs, list views, prose and diffs.
- A navy title bar with the wordmark, the two tabs as raised tabs below it.
- Square corners everywhere. No shadows except the 1px drop edge of an open
  menu.
- State is text plus color: a status label always says what it means.

## Colors

All colors are custom properties on `:root` in `app.css`; dark mode
redefines the same tokens and nothing else.

- **Face** (`--face`): panels, buttons, table heads, tabs, menus.
- **Ground** (`--ground`): the page behind the panels.
- **Field** (`--field`): inputs, list views, prose, diffs, status labels.
- **Bevel light / dark** (`--hi`, `--lo`): the two edges of every raised or
  sunken control. `--edge` is the outer line of a default button, the title
  bar's bottom and an open menu's drop edge.
- **Ink** (`--text`, `--text-2`, `--text-3`): body; secondary lines and
  captions; tertiary sub-lines and placeholders.
- **Link** (`--link`): underlined links.
- **Title bar / select** (`--title`, `--select`): the navy title bar, a
  hovered menu item or list row, the current step.
- **Ok** (`--ok`): green text on approved and up labels.
- **Danger** (`--danger`, `--danger-text`): white-on-maroon labels and
  notices for changed, down, refused and sensitive; `--danger-text` for the
  label of a destructive button or menu item (lighter in dark mode).
- **Mark** (`--mark`, `--on-mark`): a hidden code point in a tool's text.

## Typography

One face, the platform's system font, at 13px; mono for anything a machine
matches on (tool names, subjects, fingerprints, schemas, diffs). Page titles
are 20px bold, section titles 14px bold, captions 12px in secondary ink.
Labels and buttons are sentence case. No letter-spacing, no uppercase.

## Components

- **Buttons:** face fill, raised bevel, square, 26px (22px small). Pressed,
  the bevel flips to sunken and the label shifts one pixel. The default
  action (`.primary`) is bold with a 1px black outline. A destructive action
  (`.destructive`) has a maroon bold label.
- **Inputs:** white field, sunken bevel, square.
- **Panels (`.group`):** face fill, raised bevel; rows inside are divided by
  an etched line (dark line plus light line).
- **Tables:** a white list view; the head cells are raised face buttons.
- **Status labels (`.badge`):** a small sunken white label with bold text;
  `ok` is green text, `danger` is white on maroon, `pending` is plain.
- **Tabs (`.segmented`, the top nav):** raised face tabs; the current one is
  bold (sunken white for a segmented choice).
- **Per-tool menu (`details.menu`):** an **Actions** button opening a raised
  menu panel with a 1px drop edge. Review, Approve and Clear are links to the
  tool's review page; Revoke, last below an etched separator, is a one-button
  POST form carrying the CSRF token. A hovered item is navy with white text.
- **Notices:** a raised face panel with a leading glyph; danger is white on
  maroon.
- **Disclosures:** a raised face summary row with a chevron that turns when
  open.
- **Result page:** a square bevelled icon box, the title, the summary and a
  **Done** button.

## Do's and Don'ts

### Do:
- **Do** take every color from the tokens in `app.css`.
- **Do** draw edges with the bevel tokens: raised for things you press or
  that hold controls, sunken for things you type in or read from.
- **Do** say a state in words; color only reinforces it.
- **Do** keep one default (`.primary`) button per view, with a caption
  under each consequential action that says exactly what it does.
- **Do** give every data table phone behavior: list rows for lists,
  labelled stacks otherwise.

### Don't:
- **Don't** round corners, add gradients or add shadows beyond the menu's
  1px drop edge.
- **Don't** add JavaScript, inline styles, web fonts, images or icon fonts;
  the CSP forbids them.
- **Don't** use emoji; state comes from color and text.
- **Don't** use real deployment names, hosts or paths in examples; use
  casemgmt, logsearch, docsearch, threatintel and RFC 5737 / RFC 2606
  stand-ins.
