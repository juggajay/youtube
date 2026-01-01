# JSON Contract Reference

All JSON schemas used for inter-module communication.

---

## raw_vulnerabilities.json

Output of `ingest_data.py` (before filtering):

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

---

## daily_brief_packet.json

Output of `filter_score.py` (after priority matrix):

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
    "sources": ["NVD", "CISA_KEV", "EPSS"]
  }
}
```

---

## episode_script.json

Output of `generate_script.py` (ElevenLabs-ready format):

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
      "text": "[serious tone] Good morning. We have one critical vulnerability to cover.",
      "cve_refs": [],
      "tags": ["serious tone"]
    },
    {
      "index": 1,
      "speaker": "Morgan",
      "voice_id": "EXAVITQu4vr4xnSDxMaL",
      "seed": 73621,
      "chunk_type": "spoken",
      "text": "[interruption] Hold on - what's the attack vector?",
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

### Dialogue Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `voice_id` | string | YES | ElevenLabs voice ID |
| `text` | string | YES | Spoken text with narrative tags |
| `chunk_type` | string | YES | `"spoken"` or `"contextual"` |
| `seed` | integer | YES | Fixed seed for voice consistency |

---

## audio_manifest.json

Output of `audio_engine.py`:

```json
{
  "episode_date": "2025-01-15",
  "audio_file": "output/episodes/2025-01-15/episode.mp3",
  "duration_seconds": 387,
  "format": "mp3",
  "bitrate": "320kbps",
  "chapters": [
    {"title": "Intro", "start_ms": 0, "end_ms": 15000},
    {"title": "CVE-2025-1234", "start_ms": 15000, "end_ms": 165000, "cve_id": "CVE-2025-1234"}
  ],
  "line_timestamps": [
    {"index": 0, "speaker": "Alex", "start_ms": 0, "end_ms": 8500},
    {"index": 1, "speaker": "Morgan", "start_ms": 8500, "end_ms": 15000}
  ],
  "character_timestamps": [
    {"index": 0, "characters": [{"char": "G", "start_ms": 0, "end_ms": 120}]}
  ],
  "sources": {
    "input_file": "episode_script.json",
    "tts_provider": "elevenlabs",
    "api_version": "v3"
  }
}
```

---

## video_manifest.json

Output of `video_assembler.py`:

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
    {"speaker": "Morgan", "start": 8.5, "end": 15.0}
  ],
  "sources": {
    "audio_manifest": "audio_manifest.json",
    "episode_script": "episode_script.json",
    "background": "assets/background.png"
  }
}
```

---

## publish_manifest.json

Output of `publisher.py`:

```json
{
  "episode_date": "2025-01-15",
  "published_at": "2025-01-15T08:00:00Z",
  "results": {
    "youtube": {
      "status": "public",
      "video_id": "abc123xyz",
      "url": "https://www.youtube.com/watch?v=abc123xyz",
      "title": "CRITICAL: Apache Tomcat RCE - PATCH NOW!"
    },
    "rss": {
      "status": "updated",
      "path": "output/podcast.xml"
    }
  }
}
```
