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
  "sources": {
    "input_file": "episode_script.json",
    "tts_provider": "elevenlabs",
    "api_version": "v3"
  }
}
```

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
