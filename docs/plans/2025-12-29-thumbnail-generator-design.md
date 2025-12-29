# Thumbnail Generator Design

**Date**: 2025-12-29
**Status**: Approved

## Overview

Programmatic thumbnail generator for YouTube podcast episodes. Creates click-optimized thumbnails using dynamic text overlays based on episode severity.

## Architecture

```
daily_brief_packet.json
        ↓
   [1] Load background (assets/background.png)
        ↓
   [2] Smart resize with ImageOps.fit (1280x720, center crop)
        ↓
   [3] Color grade (contrast +20%, saturation +15%)
        ↓
  [3.5] Vignette overlay (darken corners, focus center)
        ↓
   [4] Determine text using Priority Logic
        ↓
   [5] Render text with 4px black stroke
        ↓
   [6] Save thumbnail.png
```

**Dependencies**: Pillow >= 9.2.0

## Priority Logic (Urgency Hierarchy)

| Priority | Condition | Text | Color |
|----------|-----------|------|-------|
| 1 | Tier-1 vendor in CVEs | `PATCH [VENDOR]` | Red (#FF0000) |
| 2 | Critical count > 0 | `[X] CRITICAL` | Red (#FF0000) |
| 3 | High count > 0 | `[X] HIGH RISK` | Yellow (#FFD700) |
| 4 | Quiet day | `DAILY INTEL` | Cyan (#00FFFF) |

### Tier-1 Vendors (Stop The Scroll)

```python
TIER_1_VENDORS = [
    "MICROSOFT", "APPLE", "GOOGLE", "AMAZON", "AWS",
    "NVIDIA", "OPENAI", "META", "CISCO", "LINUX",
    "SAMSUNG", "TESLA"
]
```

**Rationale**: These trigger either "personal fear" (my device is unsafe) or "professional panic" (infrastructure is down). Enterprise-only vendors (Oracle, Fortinet) fall to Priority 2 for more curiosity-inducing "X CRITICAL" text.

## Text Rendering

- **Font**: Impact (bundled in assets/impact.ttf)
- **Size**: 15% of image height (108px on 720p)
- **Position**: Bottom-left, 80px padding (avoids YouTube timestamp)
- **Stroke**: 6px black (built-in Pillow stroke_width)
- **Max words**: 3

## Visual Effects

### Color Grade
- Contrast: +20%
- Saturation: +15%

### Vignette
- Radial gradient using `Image.radial_gradient()`
- Intensity: 50% (adjustable)
- Effect: Dark corners, clear center

## Output

- **File**: `output/episodes/{date}/thumbnail.png`
- **Resolution**: 1280x720 (YouTube recommended)
- **Format**: PNG

## Files

- `src/pipeline/thumbnail_generator.py` - Main implementation
- `assets/impact.ttf` - Bundled font
- `assets/background.png` - Base image (Alec & Melody)
