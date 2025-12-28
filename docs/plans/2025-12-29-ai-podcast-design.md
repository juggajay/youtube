# AI-Generated Cybersecurity Podcast: System Design

**Date:** 2025-12-29
**Status:** Draft - Pending Approval
**Niche:** Cybersecurity Vulnerability Management (B2B)

---

## Executive Summary

An autonomous AI-generated podcast delivering daily vulnerability briefings to security professionals. Positioned as a "data utility" (not entertainment), featuring two AI hosts discussing critical CVEs, patch guidance, and threat intelligence.

**Key differentiators:**
- API-first content sourcing (NVD, CISA KEV, EPSS)
- Two-voice conversational format (Analyst + Business Impact)
- Dual-output: Podcast + Companion website (SEO/AdSense)
- Human-in-the-loop review dashboard (Phase 1), fully autonomous (Phase 2)

---

## 1. System Architecture

### High-Level Flow

```
                                    +-> [Audio] -> [Podcast Platforms + YouTube]
[Data Ingestion] -> [LLM Synthesis] |
                                    +-> [Blog Post] -> [Website] -> [AdSense + Affiliates]
```

### Core Components

| Component | Purpose |
|-----------|---------|
| **Data Ingestion** | Pulls from NVD API, CISA KEV, EPSS, vendor RSS |
| **Script Generator** | LLM synthesizes data into conversational briefing |
| **Audio Engine** | ElevenLabs v3 generates two-voice discussion |
| **Video Assembler** | Static visuals + audio -> YouTube-ready 4K MP4 |
| **Thumbnail Generator** | Nano Banana Pro creates episode thumbnails |
| **Web Publisher** | Generates SEO blog post with patch links |
| **Review Dashboard** | Preview, edit, approve before publish |
| **Publisher** | Pushes to YouTube, RSS feed, podcast hosts, social |
| **Scheduler** | Orchestrates daily runs (APScheduler) |

### Database Schema (SQLite)

```sql
-- Content sources
sources (
  id, type, url, name, enabled, last_fetched
)

-- Raw vulnerability data
vulnerabilities (
  id, cve_id, description,
  cvss_score, epss_score,
  exploit_status,      -- 'none', 'poc_public', 'actively_exploited'
  patch_available,     -- boolean
  vendor, product, affected_versions,
  remediation_url,
  keyword_tags,        -- JSON array: ["RCE", "ZeroDay", etc.]
  source_json,         -- raw API response
  created_at
)

-- Generated episodes
episodes (
  id, date, status,    -- 'generating', 'pending_review', 'approved', 'published', 'nuked'
  script_json,
  audio_url, video_url, blog_url, thumbnail_url,
  transcript,
  publish_scheduled_at, published_at,
  created_at
)

-- Episode-vulnerability mapping with timestamps
episode_vulnerabilities (
  episode_id, cve_id,
  podcast_timestamp,   -- for chapter markers
  segment_order
)

-- Affiliate tracking
affiliates (
  id, name, program, tracking_url, placement, active
)

-- Nuke tracking for feedback loop
nuke_reasons (
  episode_id, reason, notes, created_at
)
```

---

## 2. Data Ingestion Pipeline

### Data Sources

| Source | Endpoint | Purpose | Update Frequency |
|--------|----------|---------|------------------|
| **NVD API v2.0** | `services.nvd.nist.gov/rest/json/cves/2.0` | Primary CVE source | Real-time |
| **CISA KEV** | `cisa.gov/.../known_exploited_vulnerabilities.json` | Actively exploited | As published |
| **EPSS API** | `api.first.org/data/v1/epss` | Exploit probability | Daily |
| **GitHub Advisory** | GraphQL API | Supply chain vulns | Real-time |
| **OSV** | `osv.dev/api` | Open source vulns | Real-time |
| **Microsoft MSRC** | RSS | Windows/Azure patches | Patch Tuesday + OOB |
| **Cisco Security** | RSS | Network device vulns | As published |
| **Red Hat CVE** | RSS | Linux ecosystem | As published |

### Priority Matrix

```
CISA KEV (actively exploited)           -> CRITICAL (always include)
CVSS >= 9.0 + EPSS > 10%                -> CRITICAL
CVSS >= 7.0 + EPSS > 30%                -> HIGH
CVSS >= 9.0 + EPSS < 10%                -> MONITOR (include if space)
Everything else                          -> SKIP
```

### Rate Limiting Strategy

NVD API requires careful handling:
- Exponential backoff: start 1s, max 60s, 3 retries
- Request with API key for higher limits
- Cache responses to avoid redundant calls

### Output

"Daily Brief Packet" - JSON containing:
- 5-15 prioritized CVEs grouped by vendor
- KEV items flagged as "actively exploited"
- EPSS scores for probability context
- Remediation URLs for each

---

## 3. Script Generation

### LLM Configuration

**Model:** Claude 3.5 Sonnet or GPT-4 Turbo
**Temperature:** 0.3 (factual, low creativity)

### System Prompt

```
You are a Senior Threat Intelligence Analyst creating a daily security briefing podcast script.

FORMAT:
- Two speakers: Alex (technical analyst) and Morgan (business impact)
- Alex provides technical details, CVE IDs, affected versions
- Morgan asks clarifying questions about business impact and remediation priority

RULES:
1. Start each vulnerability with a BLUF (Bottom Line Up Front): Who is affected and what should they do RIGHT NOW
2. Use ONLY the provided JSON data - never invent details
3. Group vulnerabilities by vendor when logical
4. Insert [pause:1.5s] tags after critical announcements
5. Insert [serious tone], [urgent], [matter-of-fact] narrative tags
6. Normalize CVE IDs: "CVE-2025-1234" becomes "C[pause:100ms]V[pause:100ms]E[pause:200ms]twenty twenty-five[pause:200ms]one two three four"
7. Expand version numbers: "9.0.82" becomes "nine dot zero dot eighty-two"
8. Total runtime target: 5-8 minutes
9. End with standard disclaimer about verifying with official sources
```

### Two-Voice Personas

| Host | Role | Tone | Tags Used |
|------|------|------|-----------|
| **Alex** | Technical Analyst | Precise, clinical, authoritative | [serious tone], [matter-of-fact] |
| **Morgan** | Business Impact | Practical, urgent, questioning | [interruption], [urgent] |

### Output Format

```json
{
  "episode_date": "2025-01-15",
  "runtime_estimate": "6:30",
  "dialogue": [
    {
      "speaker": "Alex",
      "text": "[serious tone] Good morning. We have one critical and four high-severity vulnerabilities to cover today.",
      "cve_refs": []
    },
    {
      "speaker": "Alex",
      "text": "Let's start with the most urgent. C[pause:100ms]V[pause:100ms]E[pause:200ms]twenty twenty-five[pause:200ms]one two three four affects Apache Tomcat...",
      "cve_refs": ["CVE-2025-1234"]
    },
    {
      "speaker": "Morgan",
      "text": "[interruption] Hold on - that's the web server running half our infrastructure. What's the attack vector?",
      "cve_refs": ["CVE-2025-1234"]
    }
  ]
}
```

---

## 4. Audio Engine

### API Choice

**Primary:** ElevenLabs v3 Text-to-Dialogue API
**Why:** Single API call handles multi-speaker conversation with contextual emotional flow

### Voice Configuration

```yaml
# config.yaml
voices:
  alex:
    voice_id: "pNInz6obpgDQGcFmaJgB"  # Professional male
    seed: 42819                        # Fixed for consistency
    style: "news_anchor"
  morgan:
    voice_id: "EXAVITQu4vr4xnSDxMaL"  # Professional female
    seed: 73621
    style: "documentarian"
```

### Narrative Tags Supported

| Tag | Usage | Duration |
|-----|-------|----------|
| `[pause:100ms]` | Between letters in acronyms | 100ms |
| `[pause:200ms]` | After acronym, before numbers | 200ms |
| `[pause:1s]` | After CVE ID (note-taking time) | 1s |
| `[pause:1.5s]` | After BLUF / critical announcement | 1.5s |
| `[serious tone]` | Technical exploit descriptions | - |
| `[urgent]` | KEV / actively exploited items | - |
| `[interruption]` | Morgan pivoting to business impact | - |
| `[matter-of-fact]` | Legal disclaimer | - |

### API Request

```python
response = elevenlabs.text_to_dialogue(
    dialogue=script_json["dialogue"],
    voice_settings={
        "alex": {"voice_id": config.voices.alex.voice_id, "seed": config.voices.alex.seed},
        "morgan": {"voice_id": config.voices.morgan.voice_id, "seed": config.voices.morgan.seed}
    },
    character_timestamps=True,  # For chapter markers
    watermark=is_premium_tier    # Protect paid content
)
```

### Audio Assembly

```python
# audio_engine.py

1. Load assets
   - intro_music.mp3 (5-10 seconds, fade out)
   - background_hum.mp3 (subtle, -20dB, loop)
   - outro.mp3 (with CTA, fade in)

2. Generate speech
   - POST to /v3/text-to-dialogue
   - Parse character_timestamps for chapter markers

3. Assemble (using pydub)
   - Intro (fade out over 2s)
   - Background hum starts (low volume)
   - Conversation (full volume)
   - Background hum ends
   - Outro (fade in over 2s)

4. Export
   - episode_YYYY-MM-DD.mp3 (320kbps)
   - chapters_YYYY-MM-DD.json
```

### Timestamp Extraction

API response includes timing data for automatic chapter generation:

```json
{
  "timestamps": [
    {"speaker": "Alex", "start_ms": 0, "end_ms": 12400, "text": "..."},
    {"speaker": "Morgan", "start_ms": 12400, "end_ms": 18200, "text": "..."}
  ]
}
```

Map CVE mentions to timestamps -> `episode_vulnerabilities.podcast_timestamp`

---

## 5. Video Assembly

### Visual Style (Phase 1: Static)

| Element | Description |
|---------|-------------|
| **Background** | Dark branded template (3840x2160), logo, show title |
| **Waveform** | Real-time audio visualization (center) |
| **Speaker indicator** | Subtle glow showing Alex vs Morgan |
| **Lower third** | Current CVE ID being discussed |
| **Severity badge** | CRITICAL (red), HIGH (orange) indicator |

### FFmpeg Pipeline

```bash
ffmpeg -i background.png -i waveform.mp4 -i severity_badge.png -i audio.mp3 \
  -filter_complex "
    [0:v][1:v]overlay=x=100:y=400[v1];
    [v1][2:v]overlay=x=1600:y=50[v_final]
  " \
  -map "[v_final]" \
  -map 3:a \
  -vf "scale=3840:2160:flags=lanczos" \
  -c:v libx264 -crf 18 -preset slow \
  -c:a aac -b:a 192k \
  episode_4K.mp4
```

**Key:** Upload in 4K even if assets are 1080p - YouTube grants VP9/AV1 codec for sharper text.

### Thumbnail Generation

**API:** Gemini `gemini-3-pro-image-preview` (Nano Banana Pro)

**Prompt Template:**
```
Create a professional cybersecurity podcast thumbnail.
Dark background with tech/circuit aesthetic.
Bold text: "[TOP CVE HEADLINE]"
Smaller text: "Daily Threat Brief - [DATE]"
Include severity indicator showing [CRITICAL/HIGH].
Style: Clean, professional, news-like. Not sensationalist.
```

**Output:** 3840x2160 PNG for YouTube quality.

### Future Visual Upgrades

| Level | Approach | Complexity |
|-------|----------|------------|
| Current | Static + waveform | Low |
| Level 2 | Animated lower thirds, transitions | Medium |
| Level 3 | AI avatars (HeyGen, Synthesia) | High |
| Level 4 | Dynamic topic visuals (Runway, Pika) | High |

---

## 6. Web Publisher

### Hub-and-Spoke Distribution

| Platform | Role | Automation |
|----------|------|------------|
| **Companion Blog** | SEO/AdSense, patch links, archive | WordPress/Ghost API |
| **Podcast Hosts** | Spotify, Apple, Google distribution | RSS feed update |
| **YouTube** | Video exposure, chapters, comments | YouTube Data API v3 |
| **LinkedIn/X** | Viral "Daily Alert" summary | Buffer API / Make.com |
| **Email** | Subscriber retention | Mailchimp/ConvertKit |

### Blog Post Structure

```
+----------------------------------------------------------+
| AUDIO PLAYER                    YOUTUBE EMBED            |
+----------------------------------------------------------+
|                    THE DAILY MATRIX                      |
| +----------+------+------+------------+---------------+  |
| | CVE ID   | CVSS | EPSS | Status     | Quick Action  |  |
| +----------+------+------+------------+---------------+  |
| | CVE-2025 | 9.8  | 47%  | KEV        | [Patch ->]    |  |
| | CVE-2025 | 8.1  | 12%  | PoC Public | [Patch ->]    |  |
| +----------+------+------+------------+---------------+  |
+----------------------------------------------------------+
| DETAILED BREAKDOWN                                       |
| ## CVE-2025-1234: Apache Tomcat RCE                      |
| **BLUF:** Patch to 9.0.83 immediately.                   |
| **Affected:** Apache Tomcat 9.0.0 - 9.0.82               |
| **Remediation:** [Official Advisory ->]                  |
+----------------------------------------------------------+
| RECOMMENDED TOOLS [AFFILIATE]                            |
| Need compliance tracking? Try Vanta ->                   |
+----------------------------------------------------------+
| DISCLAIMER                                               |
| Always verify with official vendor bulletins.            |
+----------------------------------------------------------+
```

### YouTube Metadata

**Title Format:**
```
Critical Apache RCE + 4 High-Severity Vulns | Daily Threat Brief [Jan 15, 2025]
```

**Description:**
```
Today's vulnerabilities:

00:00 Intro
00:15 CVE-2025-1234 - Apache Tomcat RCE [CRITICAL]
02:45 CVE-2025-1235 - Cisco IOS Buffer Overflow [HIGH]
...

Patch links: [website URL]

#Cybersecurity #CVE #ThreatIntel #InfoSec
```

### Social Post Template

```
Today's Critical Vulnerabilities:

* CVE-2025-1234: Apache Tomcat RCE (CVSS 9.8) - PATCH NOW
* CVE-2025-1235: Cisco IOS Buffer Overflow (CVSS 8.1)

Full breakdown + patch links: [blog URL]
Listen: [podcast URL]

#CyberSecurity #InfoSec #ThreatIntel
```

---

## 7. Review Dashboard

### Tech Stack

**Recommended:** Streamlit (Python-native, fast iteration)
**Alternative:** Retool (better team access controls)

### Core Views

#### Side-by-Side Validation

```
+----------------------------+--------------------------------+
| SOURCE DATA (Read-Only)    | GENERATED SCRIPT (Editable)    |
+----------------------------+--------------------------------+
| {                          | ALEX: [serious tone] We have   |
|   "cve_id": "CVE-2025-...",|  a critical vulnerability...   |
|   "cvss": 9.8,             |                  [Re-render]   |
|   ...                      |                                |
| }                          | MORGAN: [interruption] What's  |
|                            |  the attack vector?            |
|                            |                  [Re-render]   |
+----------------------------+--------------------------------+
```

#### Fact-Check Flags

LLM self-critique comparing script vs source JSON:
- Version numbers match?
- CVSS/EPSS quoted correctly?
- No invented details?

#### Link Validator

Background task pings all remediation URLs:
- 200 OK = green check
- 404/5xx = red flag, needs replacement

#### Audio Preview

Per-line playback to catch pronunciation issues before full render.

### Critical Actions

| Button | Function |
|--------|----------|
| **Re-render** | Re-generate single line via ElevenLabs (cost-saving) |
| **Preview** | Play full assembled episode |
| **Approve** | Mark ready, trigger publish pipeline |
| **Nuke** | Skip publish, log reason for feedback loop |

### Episode Queue

```
+-------------+-----------+-----------+----------+---------+
| Date        | Status    | CVE Count | Critical | Actions |
+-------------+-----------+-----------+----------+---------+
| Jan 15      | Review    | 5         | 1        | [Review]|
| Jan 14      | Published | 8         | 2        | [Stats] |
| Jan 13      | Nuked     | 1         | 0        | [View]  |
+-------------+-----------+-----------+----------+---------+
```

---

## 8. Monetization Strategy

### Tier Model

| Tier | Content | Price | Monetization |
|------|---------|-------|--------------|
| **Free** | Daily 5-min briefing | $0 | Ads + Affiliates |
| **Pro** | 15-min deep dive + raw feed | $29/mo | Subscription |
| **Enterprise** | API access + Slack integration | Custom | DaaS licensing |

### Ad Placements

| Location | Type | Target |
|----------|------|--------|
| Podcast pre-roll | DAI (Dynamic Ad Insertion) | Security vendors |
| Blog header | AdSense | High-CPC B2B tech |
| Blog sidebar | AdSense | Contextual security |
| In-matrix | Affiliate | Vanta, Drata |
| Post-breakdown | Affiliate | NordVPN, 1Password |

### High-Value Keywords (CPC Reference)

| Keyword | Estimated CPC |
|---------|---------------|
| SOC 2 Compliance Companies | $217 |
| Cybersecurity Solutions | $168 |
| Cloud Security | $126 |
| Penetration Testing Services | $114 |

### Data-as-a-Service (DaaS)

Sell cleaned, LLM-enriched JSON feed:

```json
{
  "date": "2025-01-15",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2025-1234",
      "bluf": "Patch Apache Tomcat to 9.0.83 immediately",
      "cvss": 9.8,
      "epss": 0.47,
      "human_verified": true
    }
  ]
}
```

**Value prop:** "Human-verified" flag differentiates from raw NVD.

### Strategic Partnerships

| Partner | Integration | Revenue |
|---------|-------------|---------|
| Vanta/Drata | "Are you covered?" button | Affiliate |
| SIEM vendors | Feed ingestion | Licensing |
| Training platforms | Course links per vuln type | Affiliate |

---

## 9. Daily Pipeline Schedule

```
06:00 AM  [ingest_data.py]      Pull NVD, CISA, EPSS, GitHub Advisory
06:05 AM  [filter_score.py]     Apply priority matrix, select top vulns
06:10 AM  [generate_script.py]  LLM creates Alex/Morgan dialogue
06:15 AM  [audio_engine.py]     ElevenLabs v3 Text-to-Dialogue
06:25 AM  [video_assembler.py]  FFmpeg composite -> 4K MP4
06:30 AM  [thumbnail_gen.py]    Nano Banana Pro -> 4K thumbnail
06:35 AM  [web_publisher.py]    Generate blog post + social drafts
06:40 AM  [REVIEW DASHBOARD]    Human reviews, approves
07:00 AM  [publisher.py]        Push to YouTube, RSS, Blog, Social
```

**Target:** "First coffee, first threat brief" - prime 7-9 AM commute slot.

---

## 10. Risk Management

### Platform Risk

Google/YouTube increasingly detect AI content.

**Mitigation:**
- Human-in-the-loop review adds genuine editorial value
- Unique analysis/synthesis beyond raw data
- E-E-A-T compliance: expertise, experience, authoritativeness, trust

### Hallucination Risk

Wrong version numbers or bad patch links cause operational damage.

**Mitigation:**
- LLM constrained to provided JSON only
- Fact-check flags in dashboard
- Link validator catches 404s
- Mandatory disclaimer in every episode

### Alert Fatigue

Daily emails/notifications become noise.

**Mitigation:**
- Strict priority matrix (only CRITICAL/HIGH)
- "Nuke" option for low-value days
- Track nuke reasons, feed back into LLM prompt
- Quality over quantity

---

## 11. Success Metrics

### Phase 1 (Months 1-3): Validate

- [ ] 1,000 podcast downloads/episode
- [ ] 500 YouTube views/episode
- [ ] <5 min average review time
- [ ] <2 factual errors reported

### Phase 2 (Months 4-6): Grow

- [ ] 5,000 downloads/episode
- [ ] 2,500 YouTube subscribers
- [ ] $1,000/mo ad + affiliate revenue
- [ ] Launch Pro tier

### Phase 3 (Months 7-12): Scale

- [ ] 15,000 downloads/episode
- [ ] $5,000/mo revenue
- [ ] 3 enterprise DaaS customers
- [ ] Transition to fully autonomous (no daily review)

---

## 12. Tech Stack Summary

| Layer | Technology |
|-------|------------|
| **Language** | Python 3.11+ |
| **Data APIs** | NVD v2.0, CISA KEV, EPSS, GitHub Advisory |
| **LLM** | Claude 3.5 Sonnet / GPT-4 Turbo |
| **TTS** | ElevenLabs v3 Text-to-Dialogue |
| **Image Gen** | Gemini Nano Banana Pro |
| **Video** | FFmpeg + moviepy |
| **Dashboard** | Streamlit |
| **Database** | SQLite (upgrade to PostgreSQL at scale) |
| **Scheduler** | APScheduler |
| **Web Framework** | FastAPI (API) + WordPress/Ghost (blog) |
| **Hosting** | YouTube, Buzzsprout/Captivate (podcast) |

---

## Appendix A: File Structure

```
podcast/
+-- config/
|   +-- config.yaml           # API keys, voice seeds, settings
|   +-- sources.yaml          # RSS feeds, API endpoints
+-- src/
|   +-- ingest/
|   |   +-- nvd.py
|   |   +-- cisa.py
|   |   +-- epss.py
|   |   +-- rss.py
|   +-- pipeline/
|   |   +-- filter_score.py
|   |   +-- generate_script.py
|   |   +-- audio_engine.py
|   |   +-- video_assembler.py
|   |   +-- thumbnail_gen.py
|   |   +-- web_publisher.py
|   |   +-- publisher.py
|   +-- dashboard/
|   |   +-- app.py            # Streamlit dashboard
|   +-- utils/
|       +-- db.py
|       +-- ffmpeg.py
|       +-- api_clients.py
+-- assets/
|   +-- intro_music.mp3
|   +-- outro.mp3
|   +-- background.png
|   +-- logo.png
+-- data/
|   +-- podcast.db            # SQLite database
+-- output/
|   +-- episodes/
|   +-- thumbnails/
+-- docs/
|   +-- plans/
+-- tests/
+-- requirements.txt
+-- README.md
```

---

## Appendix B: API Cost Estimates

| Service | Usage | Est. Monthly Cost |
|---------|-------|-------------------|
| ElevenLabs | ~200 min audio/mo | $22-99 (tier dependent) |
| Gemini API | ~30 thumbnail generations | ~$5-10 |
| Claude/GPT | ~30 script generations | ~$10-20 |
| NVD API | Free (with key) | $0 |
| YouTube API | Free tier sufficient | $0 |
| Hosting | Buzzsprout basic | $12 |

**Estimated total:** $50-150/month

---

*Document generated: 2025-12-29*
*Status: Awaiting approval*
