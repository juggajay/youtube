# Airtable Schema Reference

Airtable serves as the Review Dashboard for human approval workflow.

---

## Table: Vulnerabilities

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

---

## Table: Episodes

| Field | Type | Description |
|-------|------|-------------|
| `Episode_Date` | Date | Primary identifier |
| `Status` | Single select | See status flow |
| `Script_JSON` | Long text | Full episode_script.json content |
| `Vulnerabilities` | Link to Vulnerabilities | Related CVEs |
| `Audio_URL` | URL | Link to generated MP3 |
| `Video_URL` | URL | Link to generated MP4 |
| `Thumbnail_URL` | URL | Link to thumbnail |
| `YouTube_URL` | URL | After publishing |
| `Blog_URL` | URL | After publishing |
| `Editor_Notes` | Long text | Human reviewer comments |
| `Nuke_Reason` | Single select | low_severity, duplicate, etc. |
| `Created_At` | Created time | Auto-populated |
| `Published_At` | Date time | When it went live |

---

## Status Values

| Status | Meaning | Next Action |
|--------|---------|-------------|
| `Draft` | CVEs ingested, no script | Run generate_script.py |
| `Script_Generated` | Script created | Human reviews in Airtable |
| `Pending_Review` | In review queue | Human approves or nukes |
| `Approved` | Ready for rendering | db_sync.py triggers engines |
| `Rendering` | Audio/video in progress | Wait |
| `Ready_for_Upload` | MP4 ready locally | Run publisher.py |
| `Published` | Live on all platforms | Done |
| `Nuked` | Skipped this episode | Log reason |

---

## Recommended Views

| View Name | Filter | Purpose |
|-----------|--------|---------|
| `Pending Review` | Status = "Script_Generated" OR "Pending_Review" | Editor queue |
| `Ready to Render` | Status = "Approved" | Pipeline trigger |
| `Ready to Publish` | Status = "Ready_for_Upload" | Final review |
| `Published` | Status = "Published" | Archive |
| `Nuked` | Status = "Nuked" | Analysis |
| `Today's CVEs` | Episode_Date = TODAY() | Quick view |

---

## db_sync.py Functions

### Push Operations (Local → Airtable)

```python
push_vulnerabilities(daily_brief_packet: dict) -> list[str]
# After filter_score.py, pushes CVEs to Vulnerabilities table

push_episode_script(episode_date: str, script: dict, vuln_ids: list[str]) -> str
# After generate_script.py, pushes script to Episodes table

update_episode_status(episode_date: str, status: str, **kwargs) -> None
# Updates status and optional fields

mark_ready_for_upload(episode_date: str, video_path, audio_path, thumbnail_path) -> None
# After video_assembler.py completes
```

### Pull Operations (Airtable → Local)

```python
pull_approved_episodes() -> list[dict]
# Gets all episodes with Status='Approved'

pull_episode_script(episode_date: str) -> Optional[dict]
# Gets specific episode's script if approved

get_included_vulnerabilities(episode_date: str) -> list[dict]
# Gets vulns where Include_In_Episode is checked
```

### Workflow Operations

```python
begin_rendering(episode_date: str) -> None
# Marks as Rendering to prevent duplicate processing

mark_published(episode_date: str, youtube_url: str, blog_url: str) -> None
# Marks as Published with platform URLs

nuke_episode(episode_date: str, reason: str, notes: str = "") -> None
# Marks as Nuked with reason
```

---

## Environment Variables

```bash
AIRTABLE_API_KEY=your_personal_access_token
AIRTABLE_BASE_ID=appXXXXXXXXXXXXXX
```

---

## Usage Examples

```python
from db_sync import push_vulnerabilities, push_episode_script

# After filter_score.py
with open("daily_brief_packet.json") as f:
    packet = json.load(f)
vuln_ids = push_vulnerabilities(packet)

# After generate_script.py
with open("episode_script.json") as f:
    script = json.load(f)
episode_id = push_episode_script("2025-01-15", script, vuln_ids)
```
