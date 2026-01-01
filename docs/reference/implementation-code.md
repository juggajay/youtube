# Implementation Code Reference

Python code examples for pipeline modules.

---

## Priority Matrix (ingester.py)

```python
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
    priority: Optional[Priority] = None


def apply_priority_matrix(vuln: Vulnerability) -> Priority:
    """
    Apply hardcoded Priority Matrix. Runs BEFORE LLM processing.
    """
    # Rule 1: CISA KEV is always CRITICAL
    if vuln.cisa_kev:
        logger.info(f"{vuln.cve_id}: CRITICAL (CISA KEV)")
        return Priority.CRITICAL

    # Rule 2: Very high severity + reasonable exploit probability
    if vuln.cvss_score > 9.0 and vuln.epss_score > 0.10:
        logger.info(f"{vuln.cve_id}: CRITICAL (CVSS {vuln.cvss_score} + EPSS {vuln.epss_score})")
        return Priority.CRITICAL

    # Rule 3: High severity + high exploit probability
    if vuln.cvss_score > 7.0 and vuln.epss_score > 0.30:
        logger.info(f"{vuln.cve_id}: HIGH")
        return Priority.HIGH

    # Rule 4: Everything else filtered
    logger.debug(f"{vuln.cve_id}: FILTERED")
    return Priority.FILTERED


def filter_vulnerabilities(vulns: list[Vulnerability]) -> tuple[list, list]:
    """Apply Priority Matrix to all vulnerabilities."""
    included, filtered = [], []

    for vuln in vulns:
        vuln.priority = apply_priority_matrix(vuln)
        if vuln.priority in (Priority.CRITICAL, Priority.HIGH):
            included.append(vuln)
        else:
            filtered.append(vuln)

    # Sort: CRITICAL first, then by CVSS descending
    included.sort(key=lambda v: (0 if v.priority == Priority.CRITICAL else 1, -v.cvss_score))
    return included, filtered
```

---

## ElevenLabs Audio Generation (audio_engine.py)

```python
import requests
import os

ELEVENLABS_API_URL = "https://api.elevenlabs.io/v3/text-to-dialogue"


def generate_dialogue(script: dict) -> dict:
    """Generate audio using ElevenLabs v3 Text-to-Dialogue."""
    payload = {
        "dialogue": [
            {
                "voice_id": line["voice_id"],
                "text": line["text"],
                "chunk_type": line["chunk_type"],
                "voice_settings": {"seed": line["seed"]}
            }
            for line in script["dialogue"]
            if line["chunk_type"] == "spoken"
        ],
        "output_format": "mp3_44100_320",
        "timestamps": {
            "enabled": True,
            "granularity": "character"  # CRITICAL for video sync
        }
    }

    response = requests.post(
        ELEVENLABS_API_URL,
        headers={"xi-api-key": os.environ["ELEVENLABS_API_KEY"]},
        json=payload
    )
    return response.json()
```

---

## Timestamp Parsing

```python
def load_speaker_segments(manifest_path: str) -> list[dict]:
    """Load line timestamps, convert ms to seconds for FFmpeg."""
    with open(manifest_path) as f:
        manifest = json.load(f)

    return [
        {
            "speaker": line["speaker"],
            "start": line["start_ms"] / 1000.0,
            "end": line["end_ms"] / 1000.0
        }
        for line in manifest["line_timestamps"]
    ]
```

---

## db_sync.py Core Functions

```python
from pyairtable import Api
from pyairtable.formulas import match
import os
import json

api = Api(os.environ["AIRTABLE_API_KEY"])

def get_table(table_name: str):
    return api.table(os.environ["AIRTABLE_BASE_ID"], table_name)


def push_vulnerabilities(daily_brief_packet: dict) -> list[str]:
    """Push CVEs to Airtable Vulnerabilities table."""
    table = get_table("Vulnerabilities")
    episode_date = daily_brief_packet["date"]
    record_ids = []

    for vuln in daily_brief_packet["vulnerabilities"]:
        existing = table.first(match({
            "CVE_ID": vuln["cve_id"],
            "Episode_Date": episode_date
        }))

        if existing:
            record_ids.append(existing["id"])
            continue

        record = {
            "CVE_ID": vuln["cve_id"],
            "CVSS_Score": vuln["cvss_score"],
            "EPSS_Score": vuln["epss_score"],
            "Severity": vuln["severity"],
            "Episode_Date": episode_date,
            "Include_In_Episode": True
        }
        created = table.create(record)
        record_ids.append(created["id"])

    return record_ids


def pull_approved_episodes() -> list[dict]:
    """Get all episodes with Status='Approved'."""
    table = get_table("Episodes")
    approved = table.all(formula=match({"Status": "Approved"}))

    return [
        {
            "episode_date": r["fields"].get("Episode_Date"),
            "script": json.loads(r["fields"].get("Script_JSON", "{}")),
        }
        for r in approved
    ]


def update_episode_status(episode_date: str, status: str, **kwargs):
    """Update episode status and optional fields."""
    table = get_table("Episodes")
    episode = table.first(match({"Episode_Date": episode_date}))
    if episode:
        table.update(episode["id"], {"Status": status, **kwargs})
```

---

## Logging Pattern

```python
import logging

logger = logging.getLogger(__name__)

# Log input/output at INFO level
logger.info(f"Input: {input_path}")
logger.info(f"Output: {output_path}")

# Log processing stats
logger.info(f"Processed {len(items)} vulnerabilities, filtered to {len(filtered)}")

# Log filter decisions for nuke analytics
def log_filter_decision(vuln, priority):
    logger.info(
        f"FILTER_DECISION | cve={vuln.cve_id} | "
        f"cvss={vuln.cvss_score} | epss={vuln.epss_score} | "
        f"kev={vuln.cisa_kev} | result={priority.value}"
    )
```

---

## Error Handling Pattern

```python
# Good: Specific, actionable errors
if not vulnerabilities:
    raise ValueError("No vulnerabilities in daily_brief_packet.json - consider nuking episode")

# Bad: Generic errors
if not vulnerabilities:
    raise Exception("Error")
```
