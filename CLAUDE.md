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

---

## Data Ingestion & Priority Matrix (ingester.py)

### CRITICAL: This section is the Source of Truth for vulnerability filtering.

### The Priority Matrix (Hardcoded)

**This logic is applied BEFORE the LLM sees any data.** The LLM only receives pre-filtered, high-priority vulnerabilities. This prevents alert fatigue and ensures we only discuss actionable threats.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRIORITY MATRIX                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  IF cisa_kev == True                         →  CRITICAL (always)      │
│                                                                         │
│  ELSE IF cvss_score > 9.0 AND epss_score > 0.10  →  CRITICAL           │
│                                                                         │
│  ELSE IF cvss_score > 7.0 AND epss_score > 0.30  →  HIGH               │
│                                                                         │
│  ELSE                                        →  FILTERED OUT            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Implementation: ingester.py

```python
"""
ingester.py - Vulnerability ingestion with hardcoded Priority Matrix

The Priority Matrix is applied BEFORE the LLM sees the data.
Only CRITICAL and HIGH vulnerabilities pass through to the script generator.

Filtered vulnerabilities are logged but not included in the episode.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class Priority(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    FILTERED = "FILTERED"


@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: float
    epss_score: float
    cisa_kev: bool
    vendor: str
    product: str
    description: str
    remediation_url: str
    # Set by apply_priority_matrix()
    priority: Optional[Priority] = None


def apply_priority_matrix(vuln: Vulnerability) -> Priority:
    """
    Apply the hardcoded Priority Matrix to a vulnerability.

    This logic is IMMUTABLE and runs before any LLM processing.
    The LLM never sees FILTERED vulnerabilities.

    Rules (in order of precedence):
        1. CISA KEV listed -> CRITICAL (always include, actively exploited)
        2. CVSS > 9.0 AND EPSS > 0.10 -> CRITICAL (severe + likely exploited)
        3. CVSS > 7.0 AND EPSS > 0.30 -> HIGH (high severity + high probability)
        4. Everything else -> FILTERED (not included unless manual override)

    Args:
        vuln: Vulnerability object with scores populated

    Returns:
        Priority enum value
    """

    # Rule 1: CISA KEV is always CRITICAL (actively exploited in the wild)
    if vuln.cisa_kev:
        logger.info(f"{vuln.cve_id}: CRITICAL (CISA KEV listed)")
        return Priority.CRITICAL

    # Rule 2: Very high severity + reasonable exploit probability
    if vuln.cvss_score > 9.0 and vuln.epss_score > 0.10:
        logger.info(f"{vuln.cve_id}: CRITICAL (CVSS {vuln.cvss_score} + EPSS {vuln.epss_score})")
        return Priority.CRITICAL

    # Rule 3: High severity + high exploit probability
    if vuln.cvss_score > 7.0 and vuln.epss_score > 0.30:
        logger.info(f"{vuln.cve_id}: HIGH (CVSS {vuln.cvss_score} + EPSS {vuln.epss_score})")
        return Priority.HIGH

    # Rule 4: Everything else is filtered out
    logger.debug(f"{vuln.cve_id}: FILTERED (CVSS {vuln.cvss_score}, EPSS {vuln.epss_score})")
    return Priority.FILTERED


def filter_vulnerabilities(vulns: list[Vulnerability]) -> tuple[list[Vulnerability], list[Vulnerability]]:
    """
    Apply Priority Matrix to all vulnerabilities.

    Args:
        vulns: List of all ingested vulnerabilities

    Returns:
        Tuple of (included, filtered) vulnerability lists
    """
    included = []
    filtered = []

    for vuln in vulns:
        vuln.priority = apply_priority_matrix(vuln)

        if vuln.priority in (Priority.CRITICAL, Priority.HIGH):
            included.append(vuln)
        else:
            filtered.append(vuln)

    # Sort by priority (CRITICAL first) then by CVSS score descending
    included.sort(key=lambda v: (
        0 if v.priority == Priority.CRITICAL else 1,
        -v.cvss_score
    ))

    logger.info(f"Priority Matrix: {len(included)} included, {len(filtered)} filtered out")

    return included, filtered


def check_manual_override(cve_id: str, overrides: dict) -> Optional[Priority]:
    """
    Check if a CVE has a manual override from Airtable.

    Allows editor to force-include a filtered vulnerability or
    force-exclude a normally included one.

    Args:
        cve_id: The CVE identifier
        overrides: Dict of {cve_id: priority_override} from Airtable

    Returns:
        Priority override if exists, None otherwise
    """
    if cve_id in overrides:
        override = overrides[cve_id]
        logger.info(f"{cve_id}: MANUAL OVERRIDE -> {override}")
        return Priority(override)
    return None
```

### Priority Matrix Rationale

| Rule | Condition | Priority | Rationale |
|------|-----------|----------|-----------|
| 1 | `cisa_kev == True` | CRITICAL | Already being exploited in the wild. No debate. |
| 2 | `cvss > 9.0 AND epss > 0.10` | CRITICAL | Severe vulnerability with meaningful exploit probability |
| 3 | `cvss > 7.0 AND epss > 0.30` | HIGH | High severity with high likelihood of exploit |
| 4 | Everything else | FILTERED | Doesn't meet threshold for daily briefing |

### Why EPSS Matters

CVSS alone causes alert fatigue. A CVSS 10.0 vulnerability that has 0.01% chance of exploitation is less urgent than a CVSS 7.5 with 50% exploit probability.

| Scenario | CVSS | EPSS | Result | Why |
|----------|------|------|--------|-----|
| Critical + likely exploited | 9.8 | 0.47 | CRITICAL | High severity, high probability |
| Critical but theoretical | 9.5 | 0.02 | FILTERED | Severe but unlikely to be exploited |
| High + very likely | 7.5 | 0.45 | HIGH | Worth mentioning due to probability |
| Medium severity | 6.5 | 0.80 | FILTERED | Not severe enough even if likely |
| KEV listed | 7.0 | 0.15 | CRITICAL | CISA says it's being exploited NOW |

### Manual Override Flow

If an editor wants to include a filtered vulnerability (or exclude an included one):

1. Editor checks `Include_In_Episode` in Airtable Vulnerabilities table
2. `db_sync.py` pulls overrides before script generation
3. `ingester.py` applies overrides after Priority Matrix
4. Override is logged for audit trail

```python
# In the pipeline orchestrator
overrides = db_sync.get_manual_overrides(episode_date)

for vuln in vulns:
    override = check_manual_override(vuln.cve_id, overrides)
    if override:
        vuln.priority = override
```

### Output: raw_vulnerabilities.json (before filtering)

```json
{
  "date": "2025-01-15",
  "ingested_at": "2025-01-15T06:00:00Z",
  "source_stats": {
    "nvd_count": 47,
    "cisa_kev_count": 2,
    "github_advisory_count": 12
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2025-1234",
      "cvss_score": 9.8,
      "epss_score": 0.47,
      "cisa_kev": false,
      "priority": null,
      "vendor": "Apache",
      "product": "Tomcat"
    }
  ]
}
```

### Output: daily_brief_packet.json (after filtering)

```json
{
  "date": "2025-01-15",
  "generated_at": "2025-01-15T06:05:00Z",
  "filter_stats": {
    "total_ingested": 61,
    "critical_count": 3,
    "high_count": 4,
    "filtered_count": 54
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2025-1234",
      "cvss_score": 9.8,
      "epss_score": 0.47,
      "cisa_kev": false,
      "priority": "CRITICAL",
      "vendor": "Apache",
      "product": "Tomcat",
      "bluf": "If you run Tomcat 9.x, upgrade to 9.0.83 immediately."
    }
  ]
}
```

### Logging for Nuke Analytics

When episodes are nuked due to low-value content, we analyze the filtered vulnerabilities to tune the matrix:

```python
def log_filter_decision(vuln: Vulnerability, priority: Priority) -> None:
    """Log every filter decision for later analysis."""
    logger.info(
        f"FILTER_DECISION | "
        f"cve={vuln.cve_id} | "
        f"cvss={vuln.cvss_score} | "
        f"epss={vuln.epss_score} | "
        f"kev={vuln.cisa_kev} | "
        f"result={priority.value}"
    )
```

This log can be analyzed to tune thresholds if too many episodes are getting nuked.

---

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

## Airtable Review Dashboard (db_sync.py)

### CRITICAL: This section is the Source of Truth for Airtable integration.

### Overview

We use **Airtable** as our Review Dashboard instead of a custom Streamlit app. The `db_sync.py` module handles all communication between the local pipeline and Airtable using the `pyairtable` library.

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Local Pipeline │ ──────► │    Airtable     │ ──────► │  Local Pipeline │
│                 │  PUSH   │                 │  PULL   │                 │
│  - CVE Data     │         │  - Review UI    │         │  - Audio Engine │
│  - Scripts      │         │  - Approval     │         │  - Video Engine │
│  - Status       │         │  - Edits        │         │  - Publisher    │
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

### Airtable Base Structure

#### Table: `Vulnerabilities`

| Field | Type | Description |
|-------|------|-------------|
| `CVE_ID` | Single line text | Primary identifier (e.g., CVE-2025-1234) |
| `Title` | Single line text | Short description |
| `CVSS_Score` | Number | 0.0 - 10.0 |
| `EPSS_Score` | Number | 0.0 - 1.0 (probability) |
| `Severity` | Single select | CRITICAL, HIGH, MEDIUM, LOW |
| `Exploit_Status` | Single select | none, poc_public, actively_exploited |
| `KEV_Listed` | Checkbox | Is it in CISA KEV? |
| `Vendor` | Single line text | e.g., Apache, Microsoft |
| `Product` | Single line text | e.g., Tomcat, Exchange |
| `Affected_Versions` | Single line text | e.g., 9.0.0 - 9.0.82 |
| `Fixed_Version` | Single line text | e.g., 9.0.83 |
| `Remediation_URL` | URL | Link to patch/advisory |
| `BLUF` | Long text | Bottom Line Up Front |
| `Description` | Long text | Full technical description |
| `Episode_Date` | Date | Which episode this belongs to |
| `Include_In_Episode` | Checkbox | Editor decision to include |
| `Created_At` | Created time | Auto-populated |

#### Table: `Episodes`

| Field | Type | Description |
|-------|------|-------------|
| `Episode_Date` | Date | Primary identifier |
| `Status` | Single select | See status flow below |
| `Script_JSON` | Long text | Full episode_script.json content |
| `Vulnerabilities` | Link to Vulnerabilities | Related CVEs |
| `Audio_URL` | URL | Link to generated MP3 (after audio engine) |
| `Video_URL` | URL | Link to generated MP4 (after video engine) |
| `Thumbnail_URL` | URL | Link to thumbnail |
| `YouTube_URL` | URL | After publishing |
| `Blog_URL` | URL | After publishing |
| `Editor_Notes` | Long text | Human reviewer comments |
| `Nuke_Reason` | Single select | If nuked: low_severity, duplicate, etc. |
| `Created_At` | Created time | Auto-populated |
| `Published_At` | Date time | When it went live |

### Episode Status Flow

```
Draft ──► Script_Generated ──► Pending_Review ──► Approved ──► Rendering
                                    │                              │
                                    ▼                              ▼
                                  Nuked                    Ready_for_Upload ──► Published
```

| Status | Meaning | Next Action |
|--------|---------|-------------|
| `Draft` | CVEs ingested, no script yet | Run generate_script.py |
| `Script_Generated` | Script created, awaiting review | Human reviews in Airtable |
| `Pending_Review` | In review queue | Human approves or nukes |
| `Approved` | Ready for audio/video | db_sync.py triggers engines |
| `Rendering` | Audio/video in progress | Wait for completion |
| `Ready_for_Upload` | MP4 ready locally | Run publisher.py |
| `Published` | Live on all platforms | Done |
| `Nuked` | Skipped this episode | Log reason, no further action |

### Implementation: db_sync.py

```python
"""
db_sync.py - Airtable synchronization module

Handles bidirectional sync between local pipeline and Airtable review dashboard.

Dependencies:
    pip install pyairtable

Environment variables required:
    AIRTABLE_API_KEY - Personal access token
    AIRTABLE_BASE_ID - Base ID (starts with 'app')
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional

from pyairtable import Api, Table
from pyairtable.formulas import match

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

AIRTABLE_API_KEY = os.environ["AIRTABLE_API_KEY"]
AIRTABLE_BASE_ID = os.environ["AIRTABLE_BASE_ID"]

# Table names
VULNERABILITIES_TABLE = "Vulnerabilities"
EPISODES_TABLE = "Episodes"

# Initialize API
api = Api(AIRTABLE_API_KEY)


def get_table(table_name: str) -> Table:
    """Get a table instance."""
    return api.table(AIRTABLE_BASE_ID, table_name)


# =============================================================================
# PUSH: Local -> Airtable
# =============================================================================

def push_vulnerabilities(daily_brief_packet: dict) -> list[str]:
    """
    Push raw CVE data to the 'Vulnerabilities' table.

    Called after filter_score.py generates daily_brief_packet.json.

    Args:
        daily_brief_packet: Parsed JSON from daily_brief_packet.json

    Returns:
        List of Airtable record IDs for the created vulnerabilities
    """
    table = get_table(VULNERABILITIES_TABLE)
    episode_date = daily_brief_packet["date"]
    record_ids = []

    for vuln in daily_brief_packet["vulnerabilities"]:
        # Check if CVE already exists for this episode date
        existing = table.first(match({
            "CVE_ID": vuln["cve_id"],
            "Episode_Date": episode_date
        }))

        if existing:
            logger.info(f"CVE {vuln['cve_id']} already exists for {episode_date}, skipping")
            record_ids.append(existing["id"])
            continue

        # Map to Airtable fields
        record = {
            "CVE_ID": vuln["cve_id"],
            "Title": vuln.get("title", ""),
            "CVSS_Score": vuln["cvss_score"],
            "EPSS_Score": vuln["epss_score"],
            "Severity": vuln["severity"],
            "Exploit_Status": vuln.get("exploit_status", "none"),
            "KEV_Listed": vuln.get("kev_listed", False),
            "Vendor": vuln.get("vendor", ""),
            "Product": vuln.get("product", ""),
            "Affected_Versions": vuln.get("affected_versions", ""),
            "Fixed_Version": vuln.get("fixed_version", ""),
            "Remediation_URL": vuln.get("remediation_url", ""),
            "BLUF": vuln.get("bluf", ""),
            "Description": vuln.get("description", ""),
            "Episode_Date": episode_date,
            "Include_In_Episode": True  # Default to include, editor can uncheck
        }

        created = table.create(record)
        record_ids.append(created["id"])
        logger.info(f"Pushed {vuln['cve_id']} to Airtable: {created['id']}")

    return record_ids


def push_episode_script(episode_date: str, script: dict, vuln_record_ids: list[str]) -> str:
    """
    Push generated script to Episodes table, link to vulnerabilities.

    Called after generate_script.py creates episode_script.json.

    Args:
        episode_date: YYYY-MM-DD format
        script: Parsed episode_script.json
        vuln_record_ids: Airtable record IDs from push_vulnerabilities()

    Returns:
        Airtable record ID for the episode
    """
    table = get_table(EPISODES_TABLE)

    # Check if episode already exists
    existing = table.first(match({"Episode_Date": episode_date}))

    record = {
        "Episode_Date": episode_date,
        "Status": "Script_Generated",
        "Script_JSON": json.dumps(script, indent=2),
        "Vulnerabilities": vuln_record_ids  # Link to vuln records
    }

    if existing:
        # Update existing record
        updated = table.update(existing["id"], record)
        logger.info(f"Updated episode {episode_date}: {updated['id']}")
        return updated["id"]
    else:
        # Create new record
        created = table.create(record)
        logger.info(f"Created episode {episode_date}: {created['id']}")
        return created["id"]


def update_episode_status(episode_date: str, status: str, **kwargs) -> None:
    """
    Update episode status and optional fields.

    Args:
        episode_date: YYYY-MM-DD format
        status: New status value
        **kwargs: Additional fields to update (Audio_URL, Video_URL, etc.)
    """
    table = get_table(EPISODES_TABLE)

    episode = table.first(match({"Episode_Date": episode_date}))
    if not episode:
        raise ValueError(f"Episode not found: {episode_date}")

    update_fields = {"Status": status, **kwargs}
    table.update(episode["id"], update_fields)
    logger.info(f"Updated episode {episode_date} status to {status}")


def mark_ready_for_upload(episode_date: str, video_path: str, audio_path: str, thumbnail_path: str) -> None:
    """
    Mark episode as Ready_for_Upload after MP4 is rendered locally.

    Called after video_assembler.py completes.

    Args:
        episode_date: YYYY-MM-DD format
        video_path: Local path to MP4 file
        audio_path: Local path to MP3 file
        thumbnail_path: Local path to thumbnail
    """
    # In production, you'd upload these to cloud storage and use the URLs
    # For now, we'll store local paths (or you can integrate with S3/GCS)

    update_episode_status(
        episode_date,
        status="Ready_for_Upload",
        Video_URL=f"file://{video_path}",  # Replace with cloud URL in production
        Audio_URL=f"file://{audio_path}",
        Thumbnail_URL=f"file://{thumbnail_path}"
    )

    logger.info(f"Episode {episode_date} marked Ready_for_Upload")


# =============================================================================
# PULL: Airtable -> Local
# =============================================================================

def pull_approved_episodes() -> list[dict]:
    """
    Pull all episodes with Status='Approved' to trigger Audio/Video engines.

    Called by the scheduler or manually to check for approved work.

    Returns:
        List of episode records with parsed Script_JSON
    """
    table = get_table(EPISODES_TABLE)

    approved = table.all(formula=match({"Status": "Approved"}))

    episodes = []
    for record in approved:
        fields = record["fields"]

        # Parse the script JSON
        script_json = fields.get("Script_JSON", "{}")
        try:
            script = json.loads(script_json)
        except json.JSONDecodeError:
            logger.error(f"Invalid Script_JSON for episode {fields.get('Episode_Date')}")
            continue

        episodes.append({
            "record_id": record["id"],
            "episode_date": fields.get("Episode_Date"),
            "script": script,
            "editor_notes": fields.get("Editor_Notes", ""),
            "vulnerabilities": fields.get("Vulnerabilities", [])
        })

    logger.info(f"Found {len(episodes)} approved episodes")
    return episodes


def pull_episode_script(episode_date: str) -> Optional[dict]:
    """
    Pull a specific episode's script by date.

    Args:
        episode_date: YYYY-MM-DD format

    Returns:
        Parsed script dict, or None if not found/not approved
    """
    table = get_table(EPISODES_TABLE)

    episode = table.first(match({"Episode_Date": episode_date}))
    if not episode:
        logger.warning(f"Episode not found: {episode_date}")
        return None

    fields = episode["fields"]
    status = fields.get("Status", "")

    if status != "Approved":
        logger.warning(f"Episode {episode_date} is not approved (status: {status})")
        return None

    script_json = fields.get("Script_JSON", "{}")
    return json.loads(script_json)


def get_included_vulnerabilities(episode_date: str) -> list[dict]:
    """
    Get vulnerabilities where Include_In_Episode is checked.

    Allows editor to uncheck CVEs they don't want in the episode.

    Args:
        episode_date: YYYY-MM-DD format

    Returns:
        List of vulnerability records that should be included
    """
    table = get_table(VULNERABILITIES_TABLE)

    vulns = table.all(formula=f"AND({{Episode_Date}}='{episode_date}', {{Include_In_Episode}}=TRUE())")

    return [
        {
            "cve_id": v["fields"]["CVE_ID"],
            "cvss_score": v["fields"]["CVSS_Score"],
            "epss_score": v["fields"]["EPSS_Score"],
            "severity": v["fields"]["Severity"],
            "bluf": v["fields"].get("BLUF", ""),
            "vendor": v["fields"].get("Vendor", ""),
            "product": v["fields"].get("Product", "")
        }
        for v in vulns
    ]


# =============================================================================
# Workflow Integration
# =============================================================================

def begin_rendering(episode_date: str) -> None:
    """
    Mark episode as Rendering before starting audio/video generation.

    Prevents duplicate processing if scheduler runs again.
    """
    update_episode_status(episode_date, status="Rendering")


def mark_published(episode_date: str, youtube_url: str, blog_url: str) -> None:
    """
    Mark episode as Published with platform URLs.

    Called after publisher.py completes.
    """
    update_episode_status(
        episode_date,
        status="Published",
        YouTube_URL=youtube_url,
        Blog_URL=blog_url,
        Published_At=datetime.utcnow().isoformat()
    )


def nuke_episode(episode_date: str, reason: str, notes: str = "") -> None:
    """
    Mark episode as Nuked with reason.

    Called when editor decides to skip this episode.
    """
    update_episode_status(
        episode_date,
        status="Nuked",
        Nuke_Reason=reason,
        Editor_Notes=notes
    )
    logger.info(f"Episode {episode_date} nuked: {reason}")


# =============================================================================
# Polling / Scheduler Integration
# =============================================================================

def poll_for_approved_work() -> None:
    """
    Main polling function for the scheduler.

    Checks for approved episodes and triggers the rendering pipeline.
    """
    approved = pull_approved_episodes()

    for episode in approved:
        episode_date = episode["episode_date"]
        logger.info(f"Processing approved episode: {episode_date}")

        # Mark as rendering to prevent re-processing
        begin_rendering(episode_date)

        # Write script to local file for audio_engine.py
        script_path = f"output/episodes/{episode_date}/episode_script.json"
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, "w") as f:
            json.dump(episode["script"], f, indent=2)

        logger.info(f"Wrote script to {script_path}")

        # The scheduler or orchestrator would now call:
        # 1. audio_engine.py
        # 2. video_assembler.py
        # 3. thumbnail_gen.py
        # 4. mark_ready_for_upload()
```

### Usage Examples

#### After filter_score.py:
```python
from db_sync import push_vulnerabilities

with open("daily_brief_packet.json") as f:
    packet = json.load(f)

vuln_ids = push_vulnerabilities(packet)
```

#### After generate_script.py:
```python
from db_sync import push_episode_script

with open("episode_script.json") as f:
    script = json.load(f)

episode_id = push_episode_script("2025-01-15", script, vuln_ids)
```

#### Scheduler polling:
```python
from db_sync import poll_for_approved_work

# Run every 5 minutes
poll_for_approved_work()
```

#### After video_assembler.py:
```python
from db_sync import mark_ready_for_upload

mark_ready_for_upload(
    episode_date="2025-01-15",
    video_path="/output/episodes/2025-01-15/episode_4K.mp4",
    audio_path="/output/episodes/2025-01-15/episode.mp3",
    thumbnail_path="/output/episodes/2025-01-15/thumbnail.png"
)
```

### Airtable Views (Recommended Setup)

Create these views in Airtable for efficient workflow:

| View Name | Filter | Purpose |
|-----------|--------|---------|
| `Pending Review` | Status = "Script_Generated" OR "Pending_Review" | Editor's main queue |
| `Ready to Render` | Status = "Approved" | What the pipeline should process |
| `Ready to Publish` | Status = "Ready_for_Upload" | Final review before going live |
| `Published` | Status = "Published" | Archive of completed episodes |
| `Nuked` | Status = "Nuked" | Track skipped episodes for analysis |
| `Today's CVEs` | Episode_Date = TODAY() | Quick view of today's vulnerabilities |

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

# Airtable (Review Dashboard)
AIRTABLE_API_KEY=your_personal_access_token
AIRTABLE_BASE_ID=appXXXXXXXXXXXXXX   # Starts with 'app'

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
1. ingest_data.py      - Pull from APIs (NVD, CISA, EPSS)
2. filter_score.py     - Apply priority matrix
3. db_sync.py          - Push CVEs to Airtable (Vulnerabilities table)
4. generate_script.py  - LLM creates dialogue
5. db_sync.py          - Push script to Airtable (Episodes table)
   ─────────────────── HUMAN REVIEW IN AIRTABLE ───────────────────
6. db_sync.py          - Poll for Approved episodes
7. audio_engine.py     - TTS generation (ElevenLabs v3)
8. video_assembler.py  - Create MP4 (FFmpeg filtergraph)
9. thumbnail_gen.py    - Create thumbnail (Nano Banana Pro)
10. db_sync.py         - Update status to Ready_for_Upload
    ─────────────────── OPTIONAL FINAL REVIEW ───────────────────
11. publisher.py       - Push to YouTube, RSS, Blog, Social
12. db_sync.py         - Update status to Published
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
