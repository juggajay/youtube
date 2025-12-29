"""
Airtable synchronization module.

Handles bidirectional sync between local pipeline and Airtable review dashboard.

When Airtable is not configured, operates in local-only mode using JSON files.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..utils import get_config, get_logger

logger = get_logger(__name__)


def _get_airtable_client():
    """
    Get Airtable client if configured.

    Returns:
        Tuple of (api, base_id) or (None, None) if not configured
    """
    config = get_config()
    env = config.get("env", {})

    api_key = env.get("airtable_api_key")
    base_id = env.get("airtable_base_id")

    if not api_key or not base_id:
        return None, None

    try:
        from pyairtable import Api
        api = Api(api_key)
        return api, base_id
    except ImportError:
        logger.warning("pyairtable not installed. Run: pip install pyairtable")
        return None, None


def _get_local_db_path() -> Path:
    """Get path for local JSON database fallback."""
    config = get_config()
    data_dir = Path(config.get("paths", {}).get("data", "data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


# =============================================================================
# PUSH: Local -> Airtable (or local JSON)
# =============================================================================

def push_vulnerabilities(daily_brief_packet: dict) -> List[str]:
    """
    Push vulnerability data to Airtable or local storage.

    Args:
        daily_brief_packet: Parsed JSON from daily_brief_packet.json

    Returns:
        List of record IDs (or CVE IDs in local mode)
    """
    api, base_id = _get_airtable_client()
    episode_date = daily_brief_packet["date"]

    if api and base_id:
        return _push_vulnerabilities_airtable(api, base_id, daily_brief_packet)
    else:
        return _push_vulnerabilities_local(daily_brief_packet)


def _push_vulnerabilities_airtable(api, base_id: str, packet: dict) -> List[str]:
    """Push to Airtable."""
    from pyairtable.formulas import match

    table = api.table(base_id, "Vulnerabilities")
    episode_date = packet["date"]
    record_ids = []

    for vuln in packet["vulnerabilities"]:
        # Check if exists
        existing = table.first(match({
            "CVE_ID": vuln["cve_id"],
            "Episode_Date": episode_date,
        }))

        if existing:
            logger.debug(f"CVE {vuln['cve_id']} already exists for {episode_date}")
            record_ids.append(existing["id"])
            continue

        record = {
            "CVE_ID": vuln["cve_id"],
            "Title": vuln.get("title", "")[:200],
            "CVSS_Score": vuln.get("cvss_score", 0),
            "EPSS_Score": vuln.get("epss_score", 0),
            "Severity": vuln.get("priority", "UNKNOWN"),
            "Exploit_Status": vuln.get("exploit_status", "none"),
            "KEV_Listed": vuln.get("cisa_kev", False),
            "Vendor": vuln.get("vendor", ""),
            "Product": vuln.get("product", ""),
            "Affected_Versions": vuln.get("affected_versions", ""),
            "Remediation_URL": vuln.get("remediation_url", ""),
            "BLUF": vuln.get("bluf", ""),
            "Description": vuln.get("description", "")[:1000],
            "Episode_Date": episode_date,
            "Include_In_Episode": True,
        }

        created = table.create(record)
        record_ids.append(created["id"])
        logger.info(f"Pushed {vuln['cve_id']} to Airtable")

    return record_ids


def _push_vulnerabilities_local(packet: dict) -> List[str]:
    """Push to local JSON storage."""
    db_path = _get_local_db_path()
    episode_date = packet["date"]

    # Save daily brief packet
    file_path = db_path / f"vulnerabilities_{episode_date}.json"
    with open(file_path, "w") as f:
        json.dump(packet, f, indent=2)

    logger.info(f"Saved vulnerabilities to {file_path}")
    return [v["cve_id"] for v in packet["vulnerabilities"]]


def push_episode_script(episode_date: str, script: dict, vuln_record_ids: List[str]) -> str:
    """
    Push generated script to Airtable or local storage.

    Args:
        episode_date: YYYY-MM-DD format
        script: Parsed episode_script.json
        vuln_record_ids: Record IDs from push_vulnerabilities

    Returns:
        Episode record ID
    """
    api, base_id = _get_airtable_client()

    if api and base_id:
        return _push_script_airtable(api, base_id, episode_date, script, vuln_record_ids)
    else:
        return _push_script_local(episode_date, script)


def _push_script_airtable(api, base_id: str, episode_date: str, script: dict, vuln_ids: List[str]) -> str:
    """Push to Airtable."""
    from pyairtable.formulas import match

    table = api.table(base_id, "Episodes")

    existing = table.first(match({"Episode_Date": episode_date}))

    record = {
        "Episode_Date": episode_date,
        "Status": "Script_Generated",
        "Script_JSON": json.dumps(script, indent=2),
        "Vulnerabilities": vuln_ids,
    }

    if existing:
        updated = table.update(existing["id"], record)
        logger.info(f"Updated episode {episode_date}")
        return updated["id"]
    else:
        created = table.create(record)
        logger.info(f"Created episode {episode_date}")
        return created["id"]


def _push_script_local(episode_date: str, script: dict) -> str:
    """Push to local JSON storage."""
    db_path = _get_local_db_path()

    # Save script
    file_path = db_path / f"episode_{episode_date}_script.json"
    with open(file_path, "w") as f:
        json.dump(script, f, indent=2)

    # Update local status
    _update_local_status(episode_date, "Script_Generated")

    logger.info(f"Saved script to {file_path}")
    return episode_date


# =============================================================================
# PULL: Airtable -> Local
# =============================================================================

def pull_approved_episodes() -> List[dict]:
    """
    Pull episodes with Status='Approved'.

    Returns:
        List of episode records with parsed scripts
    """
    api, base_id = _get_airtable_client()

    if api and base_id:
        return _pull_approved_airtable(api, base_id)
    else:
        return _pull_approved_local()


def _pull_approved_airtable(api, base_id: str) -> List[dict]:
    """Pull from Airtable."""
    from pyairtable.formulas import match

    table = api.table(base_id, "Episodes")
    approved = table.all(formula=match({"Status": "Approved"}))

    episodes = []
    for record in approved:
        fields = record["fields"]
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
        })

    logger.info(f"Found {len(episodes)} approved episodes")
    return episodes


def _pull_approved_local() -> List[dict]:
    """Pull from local JSON storage."""
    db_path = _get_local_db_path()
    status_file = db_path / "episode_status.json"

    if not status_file.exists():
        return []

    with open(status_file) as f:
        statuses = json.load(f)

    episodes = []
    for episode_date, status in statuses.items():
        if status == "Approved":
            script_file = db_path / f"episode_{episode_date}_script.json"
            if script_file.exists():
                with open(script_file) as f:
                    script = json.load(f)
                episodes.append({
                    "record_id": episode_date,
                    "episode_date": episode_date,
                    "script": script,
                    "editor_notes": "",
                })

    return episodes


# =============================================================================
# Status Updates
# =============================================================================

def update_episode_status(episode_date: str, status: str, **kwargs) -> None:
    """
    Update episode status.

    Args:
        episode_date: YYYY-MM-DD format
        status: New status value
        **kwargs: Additional fields to update
    """
    api, base_id = _get_airtable_client()

    if api and base_id:
        _update_status_airtable(api, base_id, episode_date, status, **kwargs)
    else:
        _update_local_status(episode_date, status, **kwargs)


def _update_status_airtable(api, base_id: str, episode_date: str, status: str, **kwargs) -> None:
    """Update in Airtable."""
    from pyairtable.formulas import match

    table = api.table(base_id, "Episodes")
    episode = table.first(match({"Episode_Date": episode_date}))

    if not episode:
        raise ValueError(f"Episode not found: {episode_date}")

    update_fields = {"Status": status, **kwargs}
    table.update(episode["id"], update_fields)
    logger.info(f"Updated episode {episode_date} status to {status}")


def _update_local_status(episode_date: str, status: str, **kwargs) -> None:
    """Update in local JSON."""
    db_path = _get_local_db_path()
    status_file = db_path / "episode_status.json"

    statuses = {}
    if status_file.exists():
        with open(status_file) as f:
            statuses = json.load(f)

    statuses[episode_date] = status

    with open(status_file, "w") as f:
        json.dump(statuses, f, indent=2)

    logger.info(f"Updated local status for {episode_date} to {status}")


def mark_ready_for_upload(
    episode_date: str,
    video_path: str,
    audio_path: str,
    thumbnail_path: str = "",
) -> None:
    """
    Mark episode as Ready_for_Upload after rendering.
    """
    update_episode_status(
        episode_date,
        status="Ready_for_Upload",
        Video_URL=f"file://{video_path}",
        Audio_URL=f"file://{audio_path}",
        Thumbnail_URL=f"file://{thumbnail_path}" if thumbnail_path else "",
    )
    logger.info(f"Episode {episode_date} marked Ready_for_Upload")


def mark_published(episode_date: str, youtube_url: str = "", blog_url: str = "") -> None:
    """
    Mark episode as Published.
    """
    update_episode_status(
        episode_date,
        status="Published",
        YouTube_URL=youtube_url,
        Blog_URL=blog_url,
        Published_At=datetime.utcnow().isoformat(),
    )
    logger.info(f"Episode {episode_date} marked Published")


def nuke_episode(episode_date: str, reason: str, notes: str = "") -> None:
    """
    Mark episode as Nuked (skipped).
    """
    update_episode_status(
        episode_date,
        status="Nuked",
        Nuke_Reason=reason,
        Editor_Notes=notes,
    )
    logger.info(f"Episode {episode_date} nuked: {reason}")


# =============================================================================
# Local-only helpers
# =============================================================================

def approve_episode_local(episode_date: str) -> None:
    """
    Approve an episode locally (for testing without Airtable).
    """
    _update_local_status(episode_date, "Approved")
    logger.info(f"Episode {episode_date} approved locally")


def list_local_episodes() -> dict:
    """
    List all local episodes and their statuses.
    """
    db_path = _get_local_db_path()
    status_file = db_path / "episode_status.json"

    if not status_file.exists():
        return {}

    with open(status_file) as f:
        return json.load(f)
