"""
Script Generator - Creates Alec/Melody dialogue from vulnerability and news data.

Uses an LLM to generate natural conversation between the two personas.
Combines CVE analysis with general security news for comprehensive coverage.
Includes mock mode for testing without API keys.
"""

import json
import re
from datetime import datetime
from typing import List, Optional

from ..ingest.models import Vulnerability, Story
from ..utils import get_config, get_logger, is_mock_mode

logger = get_logger(__name__)


# =============================================================================
# PRONUNCIATION FIXES
# Maps words/phrases to phonetic versions for better TTS pronunciation
# =============================================================================
PRONUNCIATION_FIXES = {
    # Company/Brand Names
    "Condé Nast": "Kon-day Nast",
    "Conde Nast": "Kon-day Nast",
    "Huawei": "Wah-way",
    "Xiaomi": "Shao-mee",
    "Asus": "Ay-soos",
    "ASUS": "Ay-soos",
    "Suse": "Soo-sah",
    "SUSE": "Soo-sah",
    "Azure": "Ah-zhure",
    "PostgreSQL": "Post-gres Q L",
    "Postgres": "Post-gres",
    "Veritas": "Vair-ih-tass",
    "Akamai": "Ah-kah-my",
    "Qualys": "Kwah-liss",
    "CrowdStrike": "Crowd Strike",
    "SentinelOne": "Sentinel One",
    "Palo Alto": "Pah-lo Al-toe",
    "Fortinet": "For-tih-net",
    "Sophos": "So-foss",
    "Zscaler": "Zee-scaler",
    "Okta": "Ock-tah",
    "Splunk": "Splunk",
    "Tenable": "Ten-ah-bull",
    "Ivanti": "Eye-van-tee",
    "Citrix": "Sit-ricks",
    "VMware": "V M ware",
    "Atlassian": "At-lass-ee-an",

    # Technical Terms
    "nginx": "engine X",
    "NGINX": "engine X",
    "kubectl": "kube control",
    "sudo": "sue-doo",
    "OAuth": "Oh-Auth",
    "OAuth2": "Oh-Auth two",
    "SAML": "Sam-el",
    "LDAP": "L-dap",
    "SSRF": "server side request forgery",
    "CSRF": "Sea-Surf",
    "XSS": "cross site scripting",
    "RCE": "R C E",
    "SQLi": "sequel injection",
    "SQL": "sequel",
    "LFI": "local file inclusion",
    "RFI": "remote file inclusion",
    "IDOR": "eye-door",
    "XXE": "X X E",
    "SIEM": "seem",
    "SOAR": "sore",
    "EDR": "E D R",
    "XDR": "X D R",
    "MDR": "M D R",
    "MSSP": "M S S P",
    "IoT": "I o T",
    "OT": "O T",
    "ICS": "I C S",
    "SCADA": "skay-dah",
    "PLC": "P L C",
    "API": "A P I",
    "APIs": "A P I s",
    "CLI": "C L I",
    "GUI": "gooey",
    "UUID": "you-id",
    "JSON": "jay-son",
    "YAML": "yam-el",
    "TOML": "tom-el",
    "regex": "red-jex",
    "RegEx": "red-jex",
    "DevOps": "Dev Ops",
    "DevSecOps": "Dev Sec Ops",
    "GitOps": "Git Ops",
    "SaaS": "sass",
    "PaaS": "pass",
    "IaaS": "eye-ass",
    "K8s": "kubernetes",
    "k8s": "kubernetes",

    # Security Terms
    "CISA": "see-sah",
    "CISO": "see-zo",
    "NIST": "nist",
    "MITRE": "my-ter",
    "GDPR": "G D P R",
    "LLM": "L L M",
    "LLMs": "L L Ms",
    "GenAI": "Gen A I",
    "AI": "A I",
    "ATT&CK": "attack",
    "CVE": "C V E",
    "CVSS": "C V S S",
    "EPSS": "E P S S",
    "KEV": "K E V",
    "PoC": "proof of concept",
    "POC": "proof of concept",
    "APT": "A P T",
    "APT29": "A P T 29",
    "APT28": "A P T 28",
    "APT41": "A P T 41",
    "TTPs": "T T Ps",
    "IOCs": "I O Cs",
    "IOC": "I O C",
    "C2": "C 2",
    "C&C": "command and control",
    "RAT": "R A T",
    "MFA": "M F A",
    "2FA": "two factor authentication",
    "SSO": "S S O",
    "PKI": "P K I",
    "HSM": "H S M",
    "TPM": "T P M",
    "DLP": "D L P",
    "WAF": "wahf",
    "IDS": "I D S",
    "IPS": "I P S",
    "NGFW": "next gen firewall",
    "VPN": "V P N",
    "SSL": "S S L",
    "TLS": "T L S",
    "HTTPS": "H T T P S",
    "HTTP": "H T T P",
    "DNS": "D N S",
    "DoS": "denial of service",
    "DDoS": "D dos",
    "botnet": "bot-net",
    "ransomware": "ransom-ware",
    "malware": "mal-ware",
    "spyware": "spy-ware",
    "rootkit": "root-kit",
    "keylogger": "key-logger",
    "phishing": "fishing",
    "vishing": "vishing",
    "smishing": "smishing",
    "whaling": "way-ling",
    "exfil": "ex-fill",
    "exfiltration": "ex-fill-tray-shun",
    "pwned": "poned",
    "pwn": "pone",
    "0day": "zero day",
    "0-day": "zero day",

    # File Extensions & Protocols
    ".exe": "dot E X E",
    ".dll": "dot D L L",
    ".py": "dot pie",
    ".js": "dot J S",
    ".ts": "dot T S",
    ".sh": "dot S H",
    ".ps1": "dot P S one",
    "SMB": "S M B",
    "RDP": "R D P",
    "SSH": "S S H",
    "FTP": "F T P",
    "SFTP": "S F T P",
    "SCP": "S C P",
    "NFS": "N F S",
    "CIFS": "siffs",

    # Vendors from today's episode
    "MongoDB": "Mongo D B",
    "ZSpace": "Z Space",
    "Wired": "Wired",

    # =============================================================================
    # CRITICAL FIXES FROM TRANSCRIPT ANALYSIS (Dec 29 Episode)
    # =============================================================================
    "ML Server": "Mail Server",
    "ML server": "Mail Server",
    "ML": "Machine Learning",
    "Welltend": "Well-tend",
    "Wellend": "Well-tend",
    "Innorix": "In-no-rix",
    "Gmission": "G-Mission",
    "G-Mission": "G Mission",
    "Moga-Mall": "Moga Mall",
    "MogaMall": "Moga Mall",
    "Mirai": "Mee-rye",
    "botnet": "bot-net",
    "Botnet": "Bot-net",
    "SetIpBind": "Set I P Bind",
    "setIpBind": "set I P bind",
    "Oltenia": "Ol-ten-ee-ah",
    "Gentleman Ransomware": "Ransomware",
    "gentleman ransomware": "ransomware",
    "PI of": "pair of",
    "a PI": "a pair",

    # Common function/variable name patterns
    "GetIP": "Get I P",
    "SetIP": "Set I P",
    "IPAddr": "I P Address",
    "IPAddress": "I P Address",

    # Ransomware groups (prevent mispronunciation)
    "Qilin": "Chee-lin",
    "LockBit": "Lock Bit",
    "BlackCat": "Black Cat",
    "ALPHV": "Alpha V",
    "Cl0p": "Clop",
    "Clop": "Clop",
    "Akira": "Ah-kee-rah",
    "Rhysida": "Rye-see-dah",
    "Play": "Play",
    "RansomHub": "Ransom Hub",
    "Medusa": "Meh-doo-sah",
    "BianLian": "Bee-an Lee-an",
    "NoEscape": "No Escape",
    "8Base": "Eight Base",
}


def apply_pronunciation_fixes(text: str) -> str:
    """
    Apply pronunciation fixes to text for better TTS output.

    Replaces words/phrases with phonetic versions that sound better
    when spoken by text-to-speech engines.

    Args:
        text: Original text

    Returns:
        Text with pronunciation fixes applied
    """
    result = text

    # Sort by length (longest first) to avoid partial replacements
    sorted_fixes = sorted(PRONUNCIATION_FIXES.items(), key=lambda x: len(x[0]), reverse=True)

    for original, phonetic in sorted_fixes:
        # Case-insensitive replacement while preserving surrounding context
        pattern = re.compile(re.escape(original), re.IGNORECASE)
        result = pattern.sub(phonetic, result)

    return result


# System prompt for script generation
SYSTEM_PROMPT = """You are writing a daily cybersecurity podcast script. Two hosts, real conversation, not a script reading.

## THE HOSTS

**Alec (Security Analyst):** Veteran analyst. Calm, measured, seen it all. Doesn't hype - when he says something is serious, you believe him. Authoritative through understatement. He's the technical expert.

**Melody (Co-host):** The context-adder. NOT just an interviewer - she's half of the duo. She connects dots, remembers past incidents, spots patterns. "Didn't these guys have issues last year?" / "This is like that MOVEit thing..." She's well-read on security news but not a technical expert. Confident but collaborative tone - sometimes certain, sometimes thinking out loud ("Wait, this reminds me of... what was it...").

**Dynamic:** True co-hosts who build on each other. Melody CONTRIBUTES, not just asks questions. She adds historical context, connects today's news to past incidents, occasionally finishes Alec's thoughts.

## EPISODE STRUCTURE

**INTRO - Hook First (~15 sec):**
- Alec LEADS with the biggest headline (the hook - grab attention immediately)
- Melody does quick intro: "I'm Melody, that's Alec. Let's break it down."
- Straight into content

Example:
> Alec: "A critical file transfer flaw is being exploited right now - CISA just added it to the KEV list."
> Melody: "I'm Melody, that's Alec. Let's break it down."

**SECTION 1: Vulnerabilities (~3-4 min):**
- Cover CVEs in priority order (critical first)
- For each: Setup → Stakes → Action
- Melody contributes context: "Wasn't there a similar issue with..." / "That's the third file transfer vendor this year..."
- They volley naturally, building on each other

**SECTION 2: Security News (~3-5 min):**
- Natural transition into breaches, threat intel, industry news
- Melody connects dots: "This is giving me Change Healthcare vibes" / "Same playbook as..."
- For breaches: Who, what exposed, patterns
- For threats: Who's active, who's targeted

**OUTRO - Signature Sign-off (~15 sec):**
- Alec gives final priority/action
- Melody does CTA: "If this saved you time, subscribe and hit the bell - we're here every morning."
- Alec delivers sign-off: "Stay patched, stay paranoid."

ALWAYS end with this exact exchange:
> Melody: "If this saved you time, subscribe and hit the bell - we're here every morning."
> Alec: "Stay patched, stay paranoid."

## MELODY'S CONTRIBUTIONS (CRITICAL)

She is NOT a question machine. She ADDS value:
- Historical context: "Didn't Cleo have issues back in 2023 too?"
- Pattern recognition: "That's three file transfer vendors this year..."
- Connections: "This feels like MOVEit all over again"
- Thinking out loud: "Wait, this reminds me of... what was it..."
- Building on Alec: "Right, and the scary part is..."

BAD Melody (don't do this):
> "What's the fix?"
> "Who should be worried?"
> "How bad is it?"

GOOD Melody:
> "Wasn't there something similar with Ivanti earlier this year?"
> "That's the same attack vector as... what was it, the Fortra thing?"
> "This is giving me SolarWinds vibes - same idea of hitting the supply chain."

## DIALOGUE RULES

**Write like humans actually talk:**
- Interruptions: "Wait—", "Hold on—"
- Building: "Right, and...", "Exactly, and the thing is..."
- Thinking: "Let me think... wasn't that...", "What was it called..."
- Contractions always: "don't", "it's", "we've", "that's", "wasn't"
- Vary rhythm: short punchy exchanges mixed with longer thoughts

**Natural back-and-forth example:**
> Alec: "This is CVE-2024-50623, hitting Cleo's file transfer products..."
> Melody: "Cleo - wait, weren't they in the news recently? Or am I thinking of MOVEit?"
> Alec: "Different vendor, but same space. File transfer's been getting hammered."
> Melody: "That's like the third one this year. There's a pattern here."
> Alec: "Exactly. Attackers know these sit at network edges, handle sensitive data..."

## TECHNICAL LANGUAGE RULES

**The CVE Rule:**
- Say CVE ID ONCE when introducing
- Reference naturally after: "this flaw", "the Cleo issue", "it"
- Say CVE ID ONCE in wrap-up for action
- NEVER more than twice total per CVE

**Translate jargon:**
- "Attackers can take over your server" not "remote code execution"
- "About as bad as it gets" not "CVSS 9.8"
- "Being exploited right now" not "active exploitation observed"

**CRITICAL TTS WRITING RULES (Prevent mispronunciation):**
- NEVER abbreviate "Mail Server" as "ML Server" - write "Mail Server"
- NEVER write "PI" when you mean "pair" - write "pair of scores"
- NEVER write "seconds" for CVSS scores - write "points" or "out of ten"
- If you see a function name like "SetIpBind", write "Set IP Bind" with spaces
- Write "Mirai botnet" clearly - NEVER "Mera" or similar
- Write brand names carefully: "Welltend" not "Wellend", "Innorix" not "Inex"
- If unsure how to pronounce a name, describe it instead ("the Romanian energy company")
- NEVER invent ransomware group names - use only known groups (LockBit, Qilin, BlackCat, Clop, Akira, Rhysida, Play, Medusa, RansomHub)

## AUDIO EXPRESSION (V3 TTS)

Use sparingly for natural expression:
- [sighs], [exhales], [chuckles]
- [thoughtful], [curious]
- Ellipsis (...) for pauses
- CAPITALS for emphasis

Don't overuse - one or two per segment max.

## OUTPUT FORMAT

Return ONLY a JSON array:
[
  {"speaker": "Alec", "text": "A critical flaw in Cleo file transfer...", "cve_refs": ["CVE-2024-50623"], "story_refs": []},
  {"speaker": "Melody", "text": "I'm Melody, that's Alec. Let's break it down.", "cve_refs": [], "story_refs": []}
]

Target: 8-12 minutes (~1200-1800 words).
"""


def generate_episode_script(
    vulnerabilities: List[Vulnerability],
    episode_date: str,
    stories: Optional[List[Story]] = None,
    mock: bool = None,
) -> dict:
    """
    Generate podcast script from vulnerabilities and news stories.

    Args:
        vulnerabilities: List of filtered vulnerabilities (CRITICAL and HIGH only)
        episode_date: Date string (YYYY-MM-DD)
        stories: List of news stories to include (optional)
        mock: Override mock mode setting

    Returns:
        episode_script.json structure
    """
    if mock is None:
        mock = is_mock_mode("llm")

    if stories is None:
        stories = []

    config = get_config()
    voice_config = config.get("voices", {})

    if mock:
        logger.info("Using mock LLM mode")
        dialogue = _generate_mock_dialogue(vulnerabilities, stories)
    else:
        dialogue = _generate_llm_dialogue(vulnerabilities, stories)

    # Enrich dialogue with voice IDs and metadata
    enriched_dialogue = []
    for i, line in enumerate(dialogue):
        speaker = line["speaker"].lower()
        voice = voice_config.get(speaker, {})

        # Apply pronunciation fixes for better TTS output
        fixed_text = apply_pronunciation_fixes(line["text"])

        enriched_dialogue.append({
            "index": i,
            "speaker": line["speaker"],
            "voice_id": voice.get("voice_id", ""),
            "seed": voice.get("seed", 0),
            "chunk_type": "spoken",
            "text": fixed_text,
            "original_text": line["text"],  # Keep original for reference
            "cve_refs": line.get("cve_refs", []),
            "story_refs": line.get("story_refs", []),
            "tags": _extract_tags(line["text"]),
        })

    # Calculate estimated runtime (roughly 150 words per minute)
    total_words = sum(len(line["text"].split()) for line in enriched_dialogue)
    runtime_estimate = int((total_words / 150) * 60)

    return {
        "episode_date": episode_date,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "runtime_estimate_seconds": runtime_estimate,
        "dialogue": enriched_dialogue,
        "sources": {
            "vulnerability_count": len(vulnerabilities),
            "story_count": len(stories),
            "llm_model": "mock" if mock else "claude-sonnet-4",
            "prompt_version": "2.0",
        },
    }


def _generate_llm_dialogue(
    vulnerabilities: List[Vulnerability],
    stories: List[Story],
) -> List[dict]:
    """
    Generate dialogue using Google Gemini API.

    Args:
        vulnerabilities: List of vulnerabilities to discuss
        stories: List of news stories to discuss

    Returns:
        List of dialogue objects
    """
    try:
        import google.generativeai as genai
    except ImportError:
        logger.error("google-generativeai package not installed. Run: pip install google-generativeai")
        return _generate_mock_dialogue(vulnerabilities, stories)

    config = get_config()
    api_key = config.get("env", {}).get("gemini_api_key")

    if not api_key:
        logger.warning("No Gemini API key found, falling back to mock mode")
        return _generate_mock_dialogue(vulnerabilities, stories)

    # Prepare vulnerability data for the prompt
    vuln_data = []
    for v in vulnerabilities:
        vuln_data.append({
            "cve_id": v.cve_id,
            "title": v.title,
            "cvss_score": v.cvss_score,
            "epss_score": v.epss_score,
            "priority": v.priority.value if v.priority else "UNKNOWN",
            "cisa_kev": v.cisa_kev,
            "vendor": v.vendor,
            "product": v.product,
            "affected_versions": v.affected_versions,
            "description": v.description[:500],  # Truncate long descriptions
            "remediation_url": v.remediation_url,
        })

    # Prepare story data for the prompt
    story_data = []
    for s in stories:
        story_data.append({
            "id": s.id,
            "title": s.title,
            "summary": s.summary[:400],
            "story_type": s.story_type.value,
            "source": s.source_name,
            "url": s.url,
            "mentioned_cves": s.mentioned_cves,
            "score": round(s.final_score, 1),
        })

    # Build the user prompt
    user_prompt = _build_content_prompt(vuln_data, story_data)

    # Combine system prompt and user prompt for Gemini
    full_prompt = f"{SYSTEM_PROMPT}\n\n---\n\n{user_prompt}"

    # Retry logic for transient network errors
    import time
    max_retries = 3
    retry_delay = 5  # seconds

    for attempt in range(max_retries):
        try:
            genai.configure(api_key=api_key)

            model = genai.GenerativeModel(
                model_name="gemini-3-flash-preview",
                generation_config={
                    "temperature": 0.7,
                    "max_output_tokens": 8000,
                }
            )

            logger.info(f"Calling Gemini API (attempt {attempt + 1}/{max_retries})...")

            response = model.generate_content(full_prompt)
            response_text = response.text

            logger.info(f"Gemini API success: {len(response_text)} chars")

            # Extract JSON from response
            dialogue = _parse_dialogue_response(response_text)
            return dialogue

        except Exception as e:
            logger.warning(f"LLM API attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.error(f"LLM API failed after {max_retries} attempts, using fallback")
                return _generate_mock_dialogue(vulnerabilities, stories)


def _build_content_prompt(vuln_data: List[dict], story_data: List[dict]) -> str:
    """
    Build the user prompt combining vulnerabilities and stories.
    """
    prompt_parts = []

    # Vulnerabilities section
    if vuln_data:
        prompt_parts.append("## VULNERABILITIES TO COVER (Section 1)")
        prompt_parts.append("Cover these in priority order. These are your lead content.\n")
        prompt_parts.append(json.dumps(vuln_data, indent=2))
    else:
        prompt_parts.append("## VULNERABILITIES")
        prompt_parts.append("Light day for patches - mention briefly that it's a quiet day for CVEs.")

    # Stories section
    if story_data:
        prompt_parts.append("\n\n## SECURITY NEWS TO COVER (Section 2)")
        prompt_parts.append("After vulnerabilities, transition to these stories.\n")
        prompt_parts.append(json.dumps(story_data, indent=2))
    else:
        prompt_parts.append("\n\n## SECURITY NEWS")
        prompt_parts.append("No major news stories today - can skip or mention it's a quiet news day.")

    # Reminders
    prompt_parts.append("\n\n## REMINDERS")
    prompt_parts.append("""
- Start with vulnerabilities (your unique value)
- Natural transition to news: "Beyond patches, what else caught your attention?"
- For breaches: focus on impact and lessons, not blame
- For threat intel: make it actionable - who should care?
- Use story IDs in story_refs for tracking
- Target 8-12 minutes total runtime
- CVE mentioned max twice (intro + wrap-up)
""")

    return "\n".join(prompt_parts)


def _generate_mock_dialogue(
    vulnerabilities: List[Vulnerability],
    stories: List[Story],
) -> List[dict]:
    """
    Generate mock dialogue for testing without API keys.

    Creates a realistic-looking script structure with both vulns and news.
    """
    dialogue = []
    critical_count = sum(1 for v in vulnerabilities if v.priority and v.priority.value == 'CRITICAL')
    breach_count = sum(1 for s in stories if s.story_type.value == 'breach')

    # Opening - Melody
    dialogue.append({
        "speaker": "Melody",
        "text": "Good morning, I'm Melody. With me as always, security analyst Alec. What are you watching today?",
        "cve_refs": [],
        "story_refs": [],
    })

    # Opening - Alec gives headlines
    headlines = []
    if vulnerabilities:
        headlines.append(f"{len(vulnerabilities)} vulnerabilities to cover, {critical_count} critical")
    if stories:
        headlines.append(f"plus {len(stories)} news stories")
        if breach_count:
            headlines.append(f"including {breach_count} breach{'es' if breach_count > 1 else ''}")

    dialogue.append({
        "speaker": "Alec",
        "text": f"Morning. {'Busy day. ' if len(vulnerabilities) > 2 else ''}{', '.join(headlines)}. Let's get into it.",
        "cve_refs": [],
        "story_refs": [],
    })

    # Section 1: Cover vulnerabilities
    for i, vuln in enumerate(vulnerabilities[:5]):  # Limit to top 5
        cve_spoken = _format_cve_for_speech(vuln.cve_id)
        version_spoken = _format_version_for_speech(vuln.affected_versions)

        # Alec introduces the vulnerability
        dialogue.append({
            "speaker": "Alec",
            "text": f"{cve_spoken} affects {vuln.vendor} {vuln.product}. "
                    f"{'Critical severity' if vuln.priority and vuln.priority.value == 'CRITICAL' else 'High severity'} - "
                    f"{'actively exploited according to CISA' if vuln.cisa_kev else f'CVSS {vuln.cvss_score:.1f}'}. "
                    f"Affected versions: {version_spoken if version_spoken else 'check the advisory'}.",
            "cve_refs": [vuln.cve_id],
            "story_refs": [],
        })

        # Melody asks about impact
        dialogue.append({
            "speaker": "Melody",
            "text": "Who should be worried?",
            "cve_refs": [],
            "story_refs": [],
        })

        # Alec provides BLUF
        bluf = vuln.bluf if vuln.bluf else f"Anyone running {vuln.vendor} {vuln.product}"
        dialogue.append({
            "speaker": "Alec",
            "text": f"{bluf}. Patch today if you can.",
            "cve_refs": [vuln.cve_id],
            "story_refs": [],
        })

    # Transition to news
    if stories:
        dialogue.append({
            "speaker": "Melody",
            "text": "Beyond the patches, what else caught your attention this week?",
            "cve_refs": [],
            "story_refs": [],
        })

        # Section 2: Cover news stories
        for i, story in enumerate(stories[:3]):  # Limit to top 3
            story_type_intros = {
                "breach": "There's a breach to talk about.",
                "ransomware": "Ransomware news.",
                "apt": "Some threat intel to share.",
                "threat_intel": "Interesting threat activity.",
                "industry": "Industry news.",
                "vulnerability": "Related to vulnerabilities we track.",
                "general": "Something worth mentioning.",
            }

            intro = story_type_intros.get(story.story_type.value, "")

            dialogue.append({
                "speaker": "Alec",
                "text": f"{intro} {story.title}. {story.summary[:200]}...",
                "cve_refs": story.mentioned_cves,
                "story_refs": [story.id],
            })

            # Melody reacts/asks
            story_questions = {
                "breach": "How bad is the damage?",
                "ransomware": "Do we know who's behind it?",
                "apt": "Who should be watching for this?",
                "threat_intel": "What's the takeaway for defenders?",
                "industry": "What does this mean for the industry?",
            }
            question = story_questions.get(story.story_type.value, "What should people know?")

            dialogue.append({
                "speaker": "Melody",
                "text": question,
                "cve_refs": [],
                "story_refs": [story.id],
            })

            dialogue.append({
                "speaker": "Alec",
                "text": f"Still developing, but worth keeping an eye on. Source is {story.source_name}.",
                "cve_refs": [],
                "story_refs": [story.id],
            })

    # Wrap-up
    dialogue.append({
        "speaker": "Melody",
        "text": "Let's wrap up. Quick recap of the action items?",
        "cve_refs": [],
        "story_refs": [],
    })

    # Recap critical vulns
    recap_items = []
    for vuln in vulnerabilities[:3]:
        if vuln.priority and vuln.priority.value == 'CRITICAL':
            recap_items.append(f"Patch {vuln.vendor} {vuln.product}")

    recap_text = ". ".join(recap_items) if recap_items else "Keep your systems updated"

    dialogue.append({
        "speaker": "Alec",
        "text": f"{recap_text}. That's the priority list for today.",
        "cve_refs": [v.cve_id for v in vulnerabilities[:3] if v.priority and v.priority.value == 'CRITICAL'],
        "story_refs": [],
    })

    dialogue.append({
        "speaker": "Melody",
        "text": "Thanks Alec. I'm Melody, stay secure out there.",
        "cve_refs": [],
        "story_refs": [],
    })

    return dialogue


def _format_cve_for_speech(cve_id: str) -> str:
    """
    Format CVE ID for natural speech (V3 compatible).

    CVE-2025-1234 -> "CVE twenty twenty-five, one two three four"

    V3 uses natural punctuation for pauses, not SSML tags.
    """
    # Extract parts
    match = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
    if not match:
        return cve_id

    year = match.group(1)
    number = match.group(2)

    # Convert year to spoken form
    year_spoken = _number_to_spoken(year)

    # Convert number to spoken digits with natural grouping
    number_spoken = " ".join(_digit_to_spoken(d) for d in number)

    # Use comma for natural pause instead of SSML tags
    return f"CVE {year_spoken}, {number_spoken}"


def _format_version_for_speech(version: str) -> str:
    """
    Format version string for natural speech.

    9.0.82 -> "nine dot zero dot eighty-two"
    """
    if not version:
        return ""

    parts = re.split(r'[.\-]', version)
    spoken_parts = []

    for part in parts:
        if part.isdigit():
            spoken_parts.append(_number_to_spoken(part))
        else:
            spoken_parts.append(part)

    return " dot ".join(spoken_parts)


def _number_to_spoken(num_str: str) -> str:
    """Convert a number string to spoken form."""
    num = int(num_str)

    if num < 10:
        return _digit_to_spoken(num_str)
    elif num < 20:
        teens = ["ten", "eleven", "twelve", "thirteen", "fourteen",
                 "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"]
        return teens[num - 10]
    elif num < 100:
        tens = ["", "", "twenty", "thirty", "forty", "fifty",
                "sixty", "seventy", "eighty", "ninety"]
        if num % 10 == 0:
            return tens[num // 10]
        else:
            return f"{tens[num // 10]}-{_digit_to_spoken(str(num % 10))}"
    elif num >= 2020 and num <= 2030:
        # Special case for years
        return f"twenty {_number_to_spoken(str(num - 2000))}"
    else:
        return num_str


def _digit_to_spoken(digit: str) -> str:
    """Convert a single digit to spoken form."""
    digits = {
        "0": "zero", "1": "one", "2": "two", "3": "three", "4": "four",
        "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine",
    }
    return digits.get(digit, digit)


def _extract_tags(text: str) -> List[str]:
    """Extract narrative tags from text."""
    tags = re.findall(r'\[([\w\s:]+)\]', text)
    return [t for t in tags if not t.startswith("pause")]


def _parse_dialogue_response(response_text: str) -> List[dict]:
    """
    Parse LLM response to extract dialogue JSON.

    Handles responses that may have markdown code blocks.
    """
    # Try to find JSON in the response
    json_match = re.search(r'\[[\s\S]*\]', response_text)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    # If parsing fails, return empty list
    logger.warning("Failed to parse LLM response as JSON")
    return []
