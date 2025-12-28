# CLAUDE.md - Project Configuration

This file is the **Source of Truth** for the AI-Generated Cybersecurity Podcast project.

---

## Project Overview

An autonomous AI-generated podcast delivering daily vulnerability briefings to security professionals. Positioned as a **data utility** (not entertainment), featuring two AI hosts discussing critical CVEs, patch guidance, and threat intelligence.

**Niche:** Cybersecurity Vulnerability Management (B2B)

---

## Voice Personas (Source of Truth)

### Alex - Technical Analyst

| Attribute | Value |
|-----------|-------|
| **Role** | Technical details, CVE IDs, affected versions, exploit mechanics |
| **Tone** | Precise, clinical, authoritative, objective |
| **Voice Style** | News anchor / documentarian |
| **ElevenLabs Voice ID** | `pNInz6obpgDQGcFmaJgB` |
| **Seed** | `42819` |
| **Narrative Tags** | `[serious tone]`, `[matter-of-fact]` |

**Alex's speech patterns:**
- States facts directly without hedging
- Uses precise technical terminology
- Reads CVE IDs with proper spacing: "C V E twenty twenty-five one two three four"
- Provides version numbers clearly: "nine dot zero dot eighty-two"
- Does not use filler words or casual language

**Example:**
> "C V E twenty twenty-five one two three four affects Apache Tomcat versions nine dot zero through nine dot zero dot eighty-two. This is a remote code execution vulnerability requiring no authentication. A public proof-of-concept exists on GitHub."

---

### Morgan - Business Impact Analyst

| Attribute | Value |
|-----------|-------|
| **Role** | Business impact, remediation priority, risk context, clarifying questions |
| **Tone** | Practical, urgent, questioning, action-oriented |
| **Voice Style** | Documentarian with slight urgency |
| **ElevenLabs Voice ID** | `EXAVITQu4vr4xnSDxMaL` |
| **Seed** | `73621` |
| **Narrative Tags** | `[interruption]`, `[urgent]` |

**Morgan's speech patterns:**
- Asks "so what?" questions to clarify business impact
- Pivots technical jargon back to actionable steps
- Uses interruptions naturally to redirect conversation
- Focuses on what listeners should DO, not just know
- Speaks with controlled urgency, not panic

**Example:**
> "Wait - that's the web server running half the internet. If I'm running Tomcat in production, what's my move here? Patch immediately, or is there a workaround while we test?"

---

### Dialogue Dynamic

The conversation follows a pattern:
1. **Alex** states the technical facts (CVE, severity, affected systems)
2. **Morgan** interrupts with business impact questions
3. **Alex** clarifies with actionable remediation
4. **Morgan** confirms the bottom line for listeners

This creates a natural flow that serves both technical and business audiences.

---

## Architecture Principle: Modular Design

### The Golden Rule

**Components communicate ONLY via standardized JSON contracts.**

Each module is a black box. The ingester doesn't care how the audio engine works. The audio engine doesn't care where the script came from. They only exchange well-defined JSON.

```
[Module A] ---> JSON Contract ---> [Module B]
```

### Why This Matters

1. **Testability** - Each module can be tested in isolation with mock JSON
2. **Replaceability** - Swap ElevenLabs for another TTS by changing one module
3. **Debugging** - Inspect the JSON between stages to find issues
4. **Parallelism** - Modules can be developed independently
5. **Auditability** - JSON contracts serve as audit logs

### Module Boundaries

```
ingest_data.py      --> raw_vulnerabilities.json
filter_score.py     --> daily_brief_packet.json
generate_script.py  --> episode_script.json
audio_engine.py     --> audio_manifest.json
video_assembler.py  --> video_manifest.json
thumbnail_gen.py    --> thumbnail_manifest.json
web_publisher.py    --> publish_manifest.json
publisher.py        --> publish_result.json
```

### JSON Contract Examples

#### daily_brief_packet.json
```json
{
  "date": "2025-01-15",
  "generated_at": "2025-01-15T06:05:00Z",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2025-1234",
      "title": "Apache Tomcat RCE",
      "cvss_score": 9.8,
      "epss_score": 0.47,
      "severity": "CRITICAL",
      "exploit_status": "poc_public",
      "kev_listed": false,
      "vendor": "Apache",
      "product": "Tomcat",
      "affected_versions": "9.0.0 - 9.0.82",
      "fixed_version": "9.0.83",
      "remediation_url": "https://tomcat.apache.org/security-9.html",
      "description": "Remote code execution via crafted request...",
      "bluf": "If you run Tomcat 9.x, upgrade to 9.0.83 immediately."
    }
  ],
  "metadata": {
    "total_ingested": 47,
    "filtered_count": 5,
    "sources": ["NVD", "CISA_KEV", "EPSS"]
  }
}
```

#### episode_script.json
```json
{
  "episode_date": "2025-01-15",
  "runtime_estimate_seconds": 390,
  "dialogue": [
    {
      "index": 0,
      "speaker": "Alex",
      "voice_id": "pNInz6obpgDQGcFmaJgB",
      "seed": 42819,
      "text": "[serious tone] Good morning. We have one critical and four high-severity vulnerabilities to cover today.",
      "cve_refs": [],
      "tags": ["serious tone"]
    },
    {
      "index": 1,
      "speaker": "Alex",
      "voice_id": "pNInz6obpgDQGcFmaJgB",
      "seed": 42819,
      "text": "Let's start with the most urgent. C[pause:100ms]V[pause:100ms]E[pause:200ms]twenty twenty-five[pause:200ms]one two three four affects Apache Tomcat...",
      "cve_refs": ["CVE-2025-1234"],
      "tags": []
    },
    {
      "index": 2,
      "speaker": "Morgan",
      "voice_id": "EXAVITQu4vr4xnSDxMaL",
      "seed": 73621,
      "text": "[interruption] Hold on - that's the web server running half our infrastructure. What's the attack vector?",
      "cve_refs": ["CVE-2025-1234"],
      "tags": ["interruption"]
    }
  ],
  "sources": {
    "input_file": "daily_brief_packet.json",
    "llm_model": "claude-3-5-sonnet",
    "prompt_version": "1.0"
  }
}
```

#### audio_manifest.json
```json
{
  "episode_date": "2025-01-15",
  "audio_file": "output/episodes/2025-01-15/episode.mp3",
  "duration_seconds": 387,
  "format": "mp3",
  "bitrate": "320kbps",
  "chapters": [
    {
      "title": "Intro",
      "start_ms": 0,
      "end_ms": 15000
    },
    {
      "title": "CVE-2025-1234 - Apache Tomcat RCE",
      "start_ms": 15000,
      "end_ms": 165000,
      "cve_id": "CVE-2025-1234"
    }
  ],
  "line_timestamps": [
    {"index": 0, "speaker": "Alex", "start_ms": 0, "end_ms": 8500},
    {"index": 1, "speaker": "Alex", "start_ms": 8500, "end_ms": 24000},
    {"index": 2, "speaker": "Morgan", "start_ms": 24000, "end_ms": 31500}
  ],
  "character_timestamps": [
    {"index": 0, "characters": [{"char": "G", "start_ms": 0, "end_ms": 120}, {"char": "o", "start_ms": 120, "end_ms": 180}]},
    {"index": 1, "characters": []},
    {"index": 2, "characters": []}
  ],
  "sources": {
    "input_file": "episode_script.json",
    "tts_provider": "elevenlabs",
    "api_version": "v3"
  }
}
```

---

## ElevenLabs v3 Text-to-Dialogue Integration

### CRITICAL: This section is the Source of Truth for audio generation.

### Script Generator Output Requirements

The `generate_script.py` module MUST output dialogue in a format compatible with ElevenLabs v3 Text-to-Dialogue. Each dialogue item requires:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `voice_id` | string | YES | ElevenLabs voice ID for this speaker |
| `text` | string | YES | The spoken text with narrative tags |
| `chunk_type` | string | YES | Either `"spoken"` or `"contextual"` |
| `seed` | integer | YES | Fixed seed for voice consistency |

#### chunk_type Values

- `"spoken"` - Normal dialogue that will be synthesized to audio
- `"contextual"` - Stage directions or context (e.g., "[Morgan looks concerned]") - NOT synthesized but used for emotional context

### episode_script.json (ElevenLabs-Ready Format)

```json
{
  "episode_date": "2025-01-15",
  "runtime_estimate_seconds": 390,
  "dialogue": [
    {
      "index": 0,
      "speaker": "Alex",
      "voice_id": "pNInz6obpgDQGcFmaJgB",
      "seed": 42819,
      "chunk_type": "spoken",
      "text": "[serious tone] Good morning. We have one critical and four high-severity vulnerabilities to cover today.",
      "cve_refs": [],
      "tags": ["serious tone"]
    },
    {
      "index": 1,
      "speaker": "Alex",
      "voice_id": "pNInz6obpgDQGcFmaJgB",
      "seed": 42819,
      "chunk_type": "spoken",
      "text": "Let's start with the most urgent. C[pause:100ms]V[pause:100ms]E[pause:200ms]twenty twenty-five[pause:200ms]one two three four affects Apache Tomcat versions nine dot zero through nine dot zero dot eighty-two. [pause:1.5s] This is a remote code execution vulnerability.",
      "cve_refs": ["CVE-2025-1234"],
      "tags": []
    },
    {
      "index": 2,
      "speaker": "Morgan",
      "voice_id": "EXAVITQu4vr4xnSDxMaL",
      "seed": 73621,
      "chunk_type": "spoken",
      "text": "[interruption] Hold on - that's the web server running half our infrastructure. What's the attack vector?",
      "cve_refs": ["CVE-2025-1234"],
      "tags": ["interruption"]
    }
  ],
  "sources": {
    "input_file": "daily_brief_packet.json",
    "llm_model": "claude-3-5-sonnet",
    "prompt_version": "1.0"
  }
}
```

### Audio Engine Implementation Requirements

The `audio_engine.py` module MUST:

#### 1. Use ElevenLabs v3 Text-to-Dialogue Endpoint

```python
# Endpoint: POST /v3/text-to-dialogue
# NOT the standard text-to-speech endpoint

import requests

ELEVENLABS_API_URL = "https://api.elevenlabs.io/v3/text-to-dialogue"
```

#### 2. Request Character-Level Timestamps

**This is CRITICAL for FFmpeg visual sync.**

```python
def generate_dialogue(script: dict) -> dict:
    """
    Generate audio using ElevenLabs v3 Text-to-Dialogue.

    MUST request character-level timestamps for video_assembler.py
    to sync visuals (speaker indicators, lower thirds, waveforms).
    """

    payload = {
        "dialogue": [
            {
                "voice_id": line["voice_id"],
                "text": line["text"],
                "chunk_type": line["chunk_type"],
                "voice_settings": {
                    "seed": line["seed"]
                }
            }
            for line in script["dialogue"]
            if line["chunk_type"] == "spoken"
        ],
        "output_format": "mp3_44100_320",

        # CRITICAL: Enable character-level timestamps
        "timestamps": {
            "enabled": True,
            "granularity": "character"  # Options: "word", "character"
        }
    }

    response = requests.post(
        ELEVENLABS_API_URL,
        headers={"xi-api-key": os.environ["ELEVENLABS_API_KEY"]},
        json=payload
    )

    return response.json()
```

#### 3. Parse Timestamp Response

The API returns character-level timing data:

```json
{
  "audio": "base64_encoded_audio...",
  "timestamps": {
    "lines": [
      {
        "line_index": 0,
        "start_ms": 0,
        "end_ms": 8500,
        "characters": [
          {"char": "G", "start_ms": 0, "end_ms": 120},
          {"char": "o", "start_ms": 120, "end_ms": 180},
          {"char": "o", "start_ms": 180, "end_ms": 240},
          {"char": "d", "start_ms": 240, "end_ms": 320}
        ]
      },
      {
        "line_index": 1,
        "start_ms": 8500,
        "end_ms": 24000,
        "characters": []
      }
    ]
  }
}
```

#### 4. Output to audio_manifest.json

The audio engine MUST write timestamps to the manifest for `video_assembler.py`:

```python
def write_audio_manifest(episode_date: str, audio_path: str, api_response: dict) -> None:
    """
    Write audio manifest with character-level timestamps.

    video_assembler.py uses these timestamps to:
    - Sync speaker indicator highlights
    - Display CVE IDs in lower thirds at exact moments
    - Generate accurate chapter markers
    - Align waveform visualization
    """

    manifest = {
        "episode_date": episode_date,
        "audio_file": audio_path,
        "duration_seconds": calculate_duration(api_response),
        "format": "mp3",
        "bitrate": "320kbps",

        # Line-level timestamps (for chapters, speaker switches)
        "line_timestamps": [
            {
                "index": line["line_index"],
                "speaker": get_speaker_for_line(line["line_index"]),
                "start_ms": line["start_ms"],
                "end_ms": line["end_ms"]
            }
            for line in api_response["timestamps"]["lines"]
        ],

        # Character-level timestamps (for precise visual sync)
        "character_timestamps": [
            {
                "index": line["line_index"],
                "characters": line["characters"]
            }
            for line in api_response["timestamps"]["lines"]
        ],

        # Chapters derived from CVE references
        "chapters": generate_chapters_from_timestamps(api_response),

        "sources": {
            "input_file": "episode_script.json",
            "tts_provider": "elevenlabs",
            "api_version": "v3"
        }
    }

    with open(f"output/episodes/{episode_date}/audio_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
```

### Why Character-Level Timestamps Matter

| Use Case | How Timestamps Are Used |
|----------|-------------------------|
| **Speaker indicator** | Highlight Alex/Morgan based on `line_timestamps[].speaker` |
| **Lower third CVE display** | Show CVE ID when character reaches that word |
| **Lip sync (future)** | Character timing enables avatar mouth movement |
| **Waveform alignment** | Precise audio-to-visual sync |
| **Chapter markers** | Accurate YouTube/Spotify chapters |
| **Re-render single line** | Know exact splice points for cost-saving edits |

---

## FFmpeg Video Assembly (video_assembler.py)

### CRITICAL: This section is the Source of Truth for video generation.

### Architecture: Complex Filtergraph

**DO NOT use simple overlays.** Use a complex filtergraph with dynamic text rendering based on ElevenLabs timestamps.

The video assembler reads `audio_manifest.json` and uses `line_timestamps[]` to determine when each speaker is active, then generates FFmpeg filters with `enable='between(t,start,end)'` to create dynamic speaker highlighting.

### Speaker Name Highlighting

When a speaker is active, their name glows. When inactive, it dims.

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
│  ┌─────────────────────────────────────────────────────┐   │
│  │  CVE-2025-1234 | Apache Tomcat RCE | CRITICAL       │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Requirements

#### 1. Parse Timestamps from audio_manifest.json

```python
def load_speaker_segments(manifest_path: str) -> list[dict]:
    """
    Load line timestamps and convert to FFmpeg-compatible time ranges.

    Returns list of segments with start/end in seconds (not ms).
    """
    with open(manifest_path) as f:
        manifest = json.load(f)

    segments = []
    for line in manifest["line_timestamps"]:
        segments.append({
            "speaker": line["speaker"],
            "start": line["start_ms"] / 1000.0,  # Convert to seconds
            "end": line["end_ms"] / 1000.0
        })

    return segments
```

#### 2. Generate Dynamic drawtext Filters

**Use `enable='between(t,start,end)'` for each speaker segment.**

```python
def generate_speaker_filters(segments: list[dict]) -> str:
    """
    Generate FFmpeg drawtext filters for dynamic speaker highlighting.

    - Active speaker: Bright text with glow effect
    - Inactive speaker: Dim text, no glow
    """

    # Collect time ranges for each speaker
    alex_ranges = [s for s in segments if s["speaker"] == "Alex"]
    morgan_ranges = [s for s in segments if s["speaker"] == "Morgan"]

    filters = []

    # --- ALEX NAME (Left side) ---

    # Base dim state (always visible)
    filters.append(
        "drawtext=text='ALEX':"
        "fontfile=/path/to/font.ttf:"
        "fontsize=48:"
        "fontcolor=0x666666:"  # Dim gray
        "x=200:y=100"
    )

    # Glow layers when Alex is speaking (stacked for glow effect)
    for seg in alex_ranges:
        # Outer glow (blur simulation with larger, semi-transparent text)
        filters.append(
            f"drawtext=text='ALEX':"
            f"fontfile=/path/to/font.ttf:"
            f"fontsize=52:"
            f"fontcolor=0x00FFFF@0.3:"  # Cyan glow, 30% opacity
            f"x=198:y=98:"
            f"enable='between(t,{seg['start']},{seg['end']})'"
        )
        # Bright text
        filters.append(
            f"drawtext=text='ALEX':"
            f"fontfile=/path/to/font.ttf:"
            f"fontsize=48:"
            f"fontcolor=0x00FFFF:"  # Bright cyan
            f"x=200:y=100:"
            f"enable='between(t,{seg['start']},{seg['end']})'"
        )

    # --- MORGAN NAME (Right side) ---

    # Base dim state
    filters.append(
        "drawtext=text='MORGAN':"
        "fontfile=/path/to/font.ttf:"
        "fontsize=48:"
        "fontcolor=0x666666:"  # Dim gray
        "x=1500:y=100"
    )

    # Glow layers when Morgan is speaking
    for seg in morgan_ranges:
        # Outer glow
        filters.append(
            f"drawtext=text='MORGAN':"
            f"fontfile=/path/to/font.ttf:"
            f"fontsize=52:"
            f"fontcolor=0xFF6600@0.3:"  # Orange glow, 30% opacity
            f"x=1498:y=98:"
            f"enable='between(t,{seg['start']},{seg['end']})'"
        )
        # Bright text
        filters.append(
            f"drawtext=text='MORGAN':"
            f"fontfile=/path/to/font.ttf:"
            f"fontsize=48:"
            f"fontcolor=0xFF6600:"  # Bright orange
            f"x=1500:y=100:"
            f"enable='between(t,{seg['start']},{seg['end']})'"
        )

    return ",".join(filters)
```

#### 3. Generate CVE Lower Third Filters

Display CVE ID when that vulnerability is being discussed:

```python
def generate_cve_filters(segments: list[dict], script: dict) -> str:
    """
    Generate lower-third CVE display based on cve_refs in script.
    """
    filters = []

    for i, seg in enumerate(segments):
        # Find corresponding script line
        script_line = script["dialogue"][i]
        cve_refs = script_line.get("cve_refs", [])

        if cve_refs:
            cve_text = cve_refs[0]  # Primary CVE for this segment

            # Background box
            filters.append(
                f"drawbox=x=100:y=980:w=1720:h=60:"
                f"color=0x000000@0.7:t=fill:"
                f"enable='between(t,{seg['start']},{seg['end']})'"
            )

            # CVE text
            filters.append(
                f"drawtext=text='{cve_text}':"
                f"fontfile=/path/to/font.ttf:"
                f"fontsize=36:"
                f"fontcolor=0xFFFFFF:"
                f"x=120:y=995:"
                f"enable='between(t,{seg['start']},{seg['end']})'"
            )

    return ",".join(filters) if filters else ""
```

#### 4. Complete Filtergraph Assembly

```python
def build_filtergraph(
    background: str,
    audio_manifest: str,
    script: str,
    waveform: str
) -> str:
    """
    Build complete FFmpeg filtergraph with all dynamic elements.

    Filtergraph order:
    1. Background image (scaled to 4K)
    2. Waveform overlay (center)
    3. Speaker names (with dynamic glow)
    4. CVE lower thirds (timed to discussion)
    5. Severity badge (static or timed)
    """

    segments = load_speaker_segments(audio_manifest)
    script_data = json.load(open(script))

    speaker_filters = generate_speaker_filters(segments)
    cve_filters = generate_cve_filters(segments, script_data)

    # Build the complete filtergraph
    filtergraph = f"""
    [0:v]scale=3840:2160[bg];
    [1:v]scale=800:200[waveform];
    [bg][waveform]overlay=x=1520:y=800[v1];
    [v1]{speaker_filters}[v2];
    [v2]{cve_filters}[v_final]
    """

    return filtergraph.replace("\n", "").replace("  ", "")
```

#### 5. FFmpeg Command Generation

```python
def generate_ffmpeg_command(
    background: str,
    waveform: str,
    audio: str,
    output: str,
    filtergraph: str
) -> str:
    """
    Generate complete FFmpeg command with complex filtergraph.

    CRITICAL: Use explicit -map to preserve audio stream.
    """

    cmd = f"""
    ffmpeg -y \\
        -loop 1 -i {background} \\
        -i {waveform} \\
        -i {audio} \\
        -filter_complex "{filtergraph}" \\
        -map "[v_final]" \\
        -map 2:a \\
        -c:v libx264 -preset slow -crf 18 \\
        -c:a aac -b:a 192k \\
        -shortest \\
        -pix_fmt yuv420p \\
        {output}
    """

    return cmd.strip()
```

### Color Scheme

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

### Glow Effect Technique

FFmpeg doesn't have native glow. Simulate with stacked text layers:

```
Layer 1: Larger text, offset -2px, 30% opacity (blur simulation)
Layer 2: Larger text, offset +2px, 30% opacity (blur simulation)
Layer 3: Normal text, full opacity (crisp center)
```

```python
def glow_layers(text: str, x: int, y: int, color: str, start: float, end: float) -> list[str]:
    """Generate 3-layer glow effect for text."""
    return [
        # Glow layer 1 (offset top-left)
        f"drawtext=text='{text}':fontsize=52:fontcolor={color}@0.3:"
        f"x={x-2}:y={y-2}:enable='between(t,{start},{end})'",

        # Glow layer 2 (offset bottom-right)
        f"drawtext=text='{text}':fontsize=52:fontcolor={color}@0.3:"
        f"x={x+2}:y={y+2}:enable='between(t,{start},{end})'",

        # Core text (crisp)
        f"drawtext=text='{text}':fontsize=48:fontcolor={color}:"
        f"x={x}:y={y}:enable='between(t,{start},{end})'",
    ]
```

### Output: video_manifest.json

```json
{
  "episode_date": "2025-01-15",
  "video_file": "output/episodes/2025-01-15/episode_4K.mp4",
  "resolution": "3840x2160",
  "duration_seconds": 387,
  "codec": "h264",
  "crf": 18,
  "dynamic_elements": {
    "speaker_highlights": true,
    "cve_lower_thirds": true,
    "waveform": true
  },
  "speaker_segments": [
    {"speaker": "Alex", "start": 0.0, "end": 8.5},
    {"speaker": "Alex", "start": 8.5, "end": 24.0},
    {"speaker": "Morgan", "start": 24.0, "end": 31.5}
  ],
  "sources": {
    "audio_manifest": "audio_manifest.json",
    "episode_script": "episode_script.json",
    "background": "assets/background.png"
  }
}
```

### Performance Considerations

| Issue | Solution |
|-------|----------|
| Many drawtext filters slow encoding | Batch similar enable ranges where possible |
| Long episodes = huge filtergraph | Consider segmented encoding, concatenate after |
| 4K is slow | Use `-preset fast` for drafts, `-preset slow` for final |
| Font loading | Use fontconfig or absolute paths to avoid lookup delays |

---

## Coding Standards

### General Principles

1. **Single Responsibility** - Each function does one thing
2. **Explicit over Implicit** - No magic, clear data flow
3. **Fail Fast** - Validate inputs early, clear error messages
4. **Log Everything** - Every module logs its input/output JSON paths

### File Naming

- Python modules: `snake_case.py`
- JSON contracts: `snake_case.json`
- Output files: `YYYY-MM-DD` prefix for date-based content

### Error Handling

```python
# Good: Specific, actionable errors
if not vulnerabilities:
    raise ValueError("No vulnerabilities in daily_brief_packet.json - consider nuking today's episode")

# Bad: Generic errors
if not vulnerabilities:
    raise Exception("Error")
```

### Logging Format

```python
import logging

logger = logging.getLogger(__name__)

# Log input/output at INFO level
logger.info(f"Input: {input_path}")
logger.info(f"Output: {output_path}")

# Log processing stats
logger.info(f"Processed {len(items)} vulnerabilities, filtered to {len(filtered)}")
```

---

## Pronunciation Rules

When generating scripts, apply these normalizations:

| Pattern | Replacement | Example |
|---------|-------------|---------|
| `CVE-XXXX-XXXXX` | `C[pause:100ms]V[pause:100ms]E[pause:200ms]` + spoken numbers | "C V E twenty twenty-five one two three four" |
| Version `X.Y.Z` | Spoken with "dot" | "9.0.82" -> "nine dot zero dot eighty-two" |
| `CVSS` | `C[pause:50ms]V[pause:50ms]S[pause:50ms]S` | Spelled out |
| `EPSS` | `E[pause:50ms]P[pause:50ms]S[pause:50ms]S` | Spelled out |
| `RCE` | "remote code execution" | Expand acronym |
| `SSRF` | "server-side request forgery" | Expand acronym |
| `XSS` | "cross-site scripting" | Expand acronym |

### Pause Hierarchy

| Context | Tag | Duration |
|---------|-----|----------|
| Between letters (acronyms) | `[pause:100ms]` | Quick spacing |
| After acronym, before number | `[pause:200ms]` | Technical clarity |
| After CVE ID (note-taking time) | `[pause:1s]` | Utility pause |
| After BLUF / critical announcement | `[pause:1.5s]` | Impact pause |

---

## Environment Variables

Required in `.env` (never commit this file):

```bash
# API Keys
ELEVENLABS_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here      # or OPENAI_API_KEY
NVD_API_KEY=your_key_here            # optional but recommended

# YouTube (OAuth credentials)
YOUTUBE_CLIENT_ID=your_client_id
YOUTUBE_CLIENT_SECRET=your_secret

# WordPress/Ghost
BLOG_API_URL=https://yourblog.com/wp-json
BLOG_API_KEY=your_key_here

# Social (optional)
BUFFER_API_KEY=your_key_here
```

---

## Design Document

Full system design: `docs/plans/2025-12-29-ai-podcast-design.md`

---

## Quick Reference

### Pipeline Order

```
1. ingest_data.py      - Pull from APIs
2. filter_score.py     - Apply priority matrix
3. generate_script.py  - LLM creates dialogue
4. audio_engine.py     - TTS generation
5. video_assembler.py  - Create MP4
6. thumbnail_gen.py    - Create thumbnail
7. web_publisher.py    - Generate blog/social
8. [REVIEW DASHBOARD]  - Human approval
9. publisher.py        - Push to platforms
```

### Key Thresholds

| Metric | Threshold |
|--------|-----------|
| CVSS Critical | >= 9.0 |
| CVSS High | >= 7.0 |
| EPSS High Probability | > 30% |
| EPSS Medium Probability | > 10% |
| Max CVEs per episode | 15 |
| Target episode length | 5-8 minutes |

### Priority Matrix

```
CISA KEV (actively exploited)    -> ALWAYS INCLUDE
CVSS >= 9.0 + EPSS > 10%         -> CRITICAL
CVSS >= 7.0 + EPSS > 30%         -> HIGH
CVSS >= 9.0 + EPSS < 10%         -> MONITOR
Everything else                   -> SKIP
```
