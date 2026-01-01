# CLAUDE.md - Project Configuration

**Source of Truth** for the AI-Generated Cybersecurity Podcast.

---

## Project Overview

Autonomous AI-generated podcast delivering daily vulnerability briefings. **Data utility** (not entertainment), featuring two AI hosts discussing critical CVEs, patch guidance, and threat intelligence.

**Niche:** Cybersecurity Vulnerability Management (B2B)

---

## Voice Personas

### Alex - Technical Analyst

| Attribute | Value |
|-----------|-------|
| **Role** | Technical details, CVE IDs, affected versions, exploit mechanics |
| **Tone** | Precise, clinical, authoritative, objective |
| **ElevenLabs Voice ID** | `pNInz6obpgDQGcFmaJgB` |
| **Seed** | `42819` |
| **Tags** | `[serious tone]`, `[matter-of-fact]` |

**Speech patterns:** States facts directly, precise terminology, no hedging or filler words.

### Morgan - Business Impact Analyst

| Attribute | Value |
|-----------|-------|
| **Role** | Business impact, remediation priority, risk context |
| **Tone** | Practical, urgent, questioning, action-oriented |
| **ElevenLabs Voice ID** | `EXAVITQu4vr4xnSDxMaL` |
| **Seed** | `73621` |
| **Tags** | `[interruption]`, `[urgent]` |

**Speech patterns:** Asks "so what?" questions, pivots jargon to actionable steps, controlled urgency.

### Dialogue Dynamic

1. **Alex** states technical facts (CVE, severity, affected systems)
2. **Morgan** interrupts with business impact questions
3. **Alex** clarifies with actionable remediation
4. **Morgan** confirms the bottom line

---

## Architecture: Modular JSON Contracts

**Components communicate ONLY via standardized JSON contracts.**

```
ingest_data.py      --> raw_vulnerabilities.json
filter_score.py     --> daily_brief_packet.json
generate_script.py  --> episode_script.json
audio_engine.py     --> audio_manifest.json
video_assembler.py  --> video_manifest.json
thumbnail_gen.py    --> thumbnail_manifest.json
publisher.py        --> publish_manifest.json
```

See `docs/reference/json-contracts.md` for schema examples.

---

## Priority Matrix

**Applied BEFORE LLM sees data.** Only CRITICAL and HIGH pass through.

| Rule | Condition | Priority |
|------|-----------|----------|
| 1 | `cisa_kev == True` | CRITICAL |
| 2 | `cvss > 9.0 AND epss > 0.10` | CRITICAL |
| 3 | `cvss > 7.0 AND epss > 0.30` | HIGH |
| 4 | Everything else | FILTERED |

Manual overrides via Airtable `Include_In_Episode` checkbox.

---

## Pronunciation Rules

| Pattern | Replacement |
|---------|-------------|
| `CVE-XXXX-XXXXX` | `C[pause:100ms]V[pause:100ms]E[pause:200ms]` + spoken numbers |
| Version `X.Y.Z` | "nine dot zero dot eighty-two" |
| `CVSS` | `C[pause:50ms]V[pause:50ms]S[pause:50ms]S` |
| `RCE` | "remote code execution" |
| `SSRF` | "server-side request forgery" |
| `XSS` | "cross-site scripting" |

### Pause Hierarchy

| Context | Duration |
|---------|----------|
| Between letters (acronyms) | `[pause:100ms]` |
| After acronym, before number | `[pause:200ms]` |
| After CVE ID | `[pause:1s]` |
| After BLUF / critical announcement | `[pause:1.5s]` |

---

## Pipeline Order

```
1. ingest_data.py      - Pull from APIs (NVD, CISA, EPSS)
2. filter_score.py     - Apply priority matrix
3. db_sync.py          - Push CVEs to Airtable
4. generate_script.py  - LLM creates dialogue
5. db_sync.py          - Push script to Airtable
   ─────────────────── HUMAN REVIEW ───────────────────
6. db_sync.py          - Poll for Approved episodes
7. audio_engine.py     - TTS generation (ElevenLabs v3)
8. video_assembler.py  - Create MP4 (FFmpeg)
9. thumbnail_gen.py    - Create thumbnail
10. publisher.py       - Push to YouTube, RSS, Blog
```

---

## Key Thresholds

| Metric | Value |
|--------|-------|
| CVSS Critical | >= 9.0 |
| CVSS High | >= 7.0 |
| EPSS High Probability | > 30% |
| EPSS Medium Probability | > 10% |
| Max CVEs per episode | 15 |
| Target episode length | 5-8 minutes |

---

## Episode Status Flow

```
Draft → Script_Generated → Pending_Review → Approved → Rendering → Ready_for_Upload → Published
                                ↓
                              Nuked
```

---

## Environment Variables

Required in `.env`:

```bash
ELEVENLABS_API_KEY=...
ANTHROPIC_API_KEY=...
NVD_API_KEY=...
AIRTABLE_API_KEY=...
AIRTABLE_BASE_ID=app...
YOUTUBE_CLIENT_ID=...
YOUTUBE_CLIENT_SECRET=...
```

---

## Coding Standards

- **Single Responsibility** - Each function does one thing
- **Explicit over Implicit** - No magic, clear data flow
- **Fail Fast** - Validate inputs early
- **Log Everything** - Every module logs input/output paths
- File naming: `snake_case.py`, `snake_case.json`
- Output files: `YYYY-MM-DD` prefix

---

## Reference Documentation

| Doc | Contents |
|-----|----------|
| `docs/reference/json-contracts.md` | All JSON schema examples |
| `docs/reference/ffmpeg-guide.md` | Video assembly, filtergraph, glow effects |
| `docs/reference/airtable-schema.md` | Table structures, db_sync patterns |
| `docs/reference/implementation-code.md` | Python code examples |
| `docs/plans/2025-12-29-ai-podcast-design.md` | Full system design |
