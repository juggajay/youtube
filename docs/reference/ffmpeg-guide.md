# FFmpeg Video Assembly Guide

Implementation reference for `video_assembler.py`.

---

## Architecture

Use a **complex filtergraph** with dynamic text rendering based on ElevenLabs timestamps. DO NOT use simple overlays.

The video assembler:
1. Reads `audio_manifest.json` for `line_timestamps[]`
2. Generates FFmpeg filters with `enable='between(t,start,end)'`
3. Creates dynamic speaker highlighting

---

## Visual Layout

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│     ╔═══════════╗              ┌───────────┐               │
│     ║   ALEX    ║   <-- GLOW   │  MORGAN   │  <-- DIM      │
│     ╚═══════════╝              └───────────┘               │
│                                                             │
│                    ┌─────────────────┐                      │
│                    │   [WAVEFORM]    │                      │
│                    └─────────────────┘                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  CVE-2025-1234 | Apache Tomcat RCE | CRITICAL          ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## Color Scheme

| Element | Active Color | Inactive Color |
|---------|--------------|----------------|
| Alex name | `0x00FFFF` (Cyan) | `0x666666` (Gray) |
| Morgan name | `0xFF6600` (Orange) | `0x666666` (Gray) |
| Alex glow | `0x00FFFF@0.3` | - |
| Morgan glow | `0xFF6600@0.3` | - |
| CVE box bg | `0x000000@0.7` | - |
| CVE text | `0xFFFFFF` | - |
| CRITICAL badge | `0xFF0000` | - |
| HIGH badge | `0xFFA500` | - |

---

## Glow Effect Technique

FFmpeg lacks native glow. Simulate with stacked text layers:

```
Layer 1: Larger text, offset -2px, 30% opacity
Layer 2: Larger text, offset +2px, 30% opacity
Layer 3: Normal text, full opacity (crisp center)
```

```python
def glow_layers(text: str, x: int, y: int, color: str, start: float, end: float) -> list[str]:
    return [
        f"drawtext=text='{text}':fontsize=52:fontcolor={color}@0.3:"
        f"x={x-2}:y={y-2}:enable='between(t,{start},{end})'",

        f"drawtext=text='{text}':fontsize=52:fontcolor={color}@0.3:"
        f"x={x+2}:y={y+2}:enable='between(t,{start},{end})'",

        f"drawtext=text='{text}':fontsize=48:fontcolor={color}:"
        f"x={x}:y={y}:enable='between(t,{start},{end})'",
    ]
```

---

## Speaker Filter Generation

```python
def generate_speaker_filters(segments: list[dict]) -> str:
    alex_ranges = [s for s in segments if s["speaker"] == "Alex"]
    morgan_ranges = [s for s in segments if s["speaker"] == "Morgan"]

    filters = []

    # Base dim state (always visible)
    filters.append(
        "drawtext=text='ALEX':fontfile=/path/to/font.ttf:"
        "fontsize=48:fontcolor=0x666666:x=200:y=100"
    )

    # Glow when speaking
    for seg in alex_ranges:
        filters.append(
            f"drawtext=text='ALEX':fontsize=48:fontcolor=0x00FFFF:"
            f"x=200:y=100:enable='between(t,{seg['start']},{seg['end']})'"
        )

    # Same pattern for Morgan with 0xFF6600 color
    return ",".join(filters)
```

---

## CVE Lower Third

```python
def generate_cve_filters(segments: list[dict], script: dict) -> str:
    filters = []
    for i, seg in enumerate(segments):
        cve_refs = script["dialogue"][i].get("cve_refs", [])
        if cve_refs:
            # Background box
            filters.append(
                f"drawbox=x=100:y=980:w=1720:h=60:color=0x000000@0.7:t=fill:"
                f"enable='between(t,{seg['start']},{seg['end']})'"
            )
            # CVE text
            filters.append(
                f"drawtext=text='{cve_refs[0]}':fontsize=36:fontcolor=0xFFFFFF:"
                f"x=120:y=995:enable='between(t,{seg['start']},{seg['end']})'"
            )
    return ",".join(filters)
```

---

## Complete Filtergraph

```python
def build_filtergraph(audio_manifest: str, script: str) -> str:
    segments = load_speaker_segments(audio_manifest)
    script_data = json.load(open(script))

    speaker_filters = generate_speaker_filters(segments)
    cve_filters = generate_cve_filters(segments, script_data)

    return f"""
    [0:v]scale=3840:2160[bg];
    [1:v]scale=800:200[waveform];
    [bg][waveform]overlay=x=1520:y=800[v1];
    [v1]{speaker_filters}[v2];
    [v2]{cve_filters}[v_final]
    """.replace("\n", "").replace("  ", "")
```

---

## FFmpeg Command

```python
def generate_ffmpeg_command(background, waveform, audio, output, filtergraph):
    return f"""
    ffmpeg -y \
        -loop 1 -i {background} \
        -i {waveform} \
        -i {audio} \
        -filter_complex "{filtergraph}" \
        -map "[v_final]" \
        -map 2:a \
        -c:v libx264 -preset slow -crf 18 \
        -c:a aac -b:a 192k \
        -shortest \
        -pix_fmt yuv420p \
        {output}
    """
```

**CRITICAL:** Use explicit `-map` to preserve audio stream.

---

## Performance Tips

| Issue | Solution |
|-------|----------|
| Many drawtext filters slow encoding | Batch similar enable ranges |
| Long episodes = huge filtergraph | Segmented encoding, concatenate after |
| 4K is slow | `-preset fast` for drafts, `-preset slow` for final |
| Font loading | Use fontconfig or absolute paths |
