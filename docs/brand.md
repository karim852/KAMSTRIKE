# KAMSTRIKE brand

## Mark

The logo is a stacked lockup: a faceted **K** monogram with a targeting reticle set into its
crook, above the **KAMSTRIKE** wordmark whose **A** is a solid chevron in the accent green.

Three vector files ship in `kamstrike/web/static/`:

| File | Use |
| --- | --- |
| `logo.svg` | the full stacked lockup — splash, README, print |
| `icon.svg` | the K monogram alone — favicon, app icon, anywhere under ~48px |
| `wordmark.svg` | the wordmark alone — paired with `icon.svg` in the dashboard header |

They were vectorised from the original artwork (kept at `docs/brand/kamstrike-logo-source.webp`),
so they stay sharp at any size and carry no raster weight.

Rules: always on black or near-black. Never recolour the white letterforms. Never stretch the
lockup — scale it. Leave clear space around it of at least the height of the reticle.

## Palette

The interface is dark only. An operator reads it during an engagement, often beside a video
wall, and a white panel at 2am is a liability — so there is no light variant to drift out of
sync. Severity hues are the only saturated colours in the UI, which keeps a critical finding
impossible to miss.

Tokens live in `kamstrike/web/static/brand.css` and are the single source of truth.

### Surfaces

| Token | Hex | Use |
| --- | --- | --- |
| `--bg` | `#000000` | page background; the logo is drawn on true black |
| `--panel` | `#0d1116` | cards, header |
| `--panel-2` | `#141a21` | inputs, nested blocks |
| `--panel-3` | `#1b222b` | hover |
| `--line` | `#222a34` | borders |

### Type

| Token | Hex | Use |
| --- | --- | --- |
| `--fg` | `#e8edf2` | primary text |
| `--fg-dim` | `#b9c2cd` | body text in dense blocks |
| `--muted` | `#7f8a98` | secondary text |
| `--faint` | `#5a6472` | labels, metadata |

### Brand

| Token | Hex | Use |
| --- | --- | --- |
| `--accent` | `#0bf5ae` | primary actions, confirmed state, live indicators |
| `--accent-dim` | `#0a9c72` | accent borders, de-emphasised accent |
| `--accent-ink` | `#04120e` | text on an accent fill |
| `--record` | `#ff2d55` | recording / live-feed cue only |

The accent is sampled from the reticle in the logo, so the interface and the mark cannot
drift apart.

### Severity

These five are reserved. Nothing else in the interface may use them, so a colour always
means a severity.

| Token | Hex |
| --- | --- |
| `--critical` | `#ff3b5c` |
| `--high` | `#ff8a3d` |
| `--medium` | `#ffc53d` |
| `--low` | `#3da5ff` |
| `--info` | `#7a8694` |

## Type stack

System fonts only — nothing is fetched from a CDN, because the dashboard has to work on an
isolated assessment network.

```
--sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
--mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace
```

Hosts, ports, URLs, payloads and anything an operator may copy are always set in `--mono`.
