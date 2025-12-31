"""
Script Validator - Pre-flight check before audio generation.

Two layers:
1. Rule-based: CVE format, vendor cross-check, known ransomware groups
2. LLM review: Catch hallucinations, factual errors, suspicious content

Saves ElevenLabs credits by catching errors before TTS.
"""

import json
import re
from typing import List, Dict, Tuple
from ..utils import get_config, get_logger

logger = get_logger(__name__)


# =============================================================================
# KNOWN VALID DATA (for cross-checking)
# =============================================================================

KNOWN_RANSOMWARE_GROUPS = {
    "LOCKBIT", "LOCKBIT 3.0", "LOCKBIT 2.0",
    "BLACKCAT", "ALPHV",
    "CLOP", "CL0P",
    "QILIN",
    "AKIRA",
    "RHYSIDA",
    "PLAY",
    "MEDUSA",
    "BIANLIAN",
    "RANSOMHUB",
    "8BASE",
    "NOESCAPE",
    "BLACK BASTA",
    "ROYAL",
    "VICE SOCIETY",
    "HIVE",
    "CONTI",
    "REVIL", "SODINOKIBI",
    "DARKSIDE",
    "BLACKMATTER",
    "AVADDON",
    "RAGNAR LOCKER",
    "MAZE",
    "NETWALKER",
    "DOPPELPAYMER",
    "EGREGOR",
    "PYSA", "MESPINOZA",
    "CUBA",
    "SNATCH",
    "PHOBOS",
    "DHARMA",
    "STOP", "DJVU",
    "MAGNIBER",
    "TRIGONA",
    "CACTUS",
    "HUNTERS INTERNATIONAL",
    "INC RANSOM",
    "GENTLEMEN",  # Romanian energy attack Dec 2025
    "LYNX",
    "FOG",
    "FUNKSEC",
}

# Common hallucination patterns to flag
SUSPICIOUS_PATTERNS = [
    r"proxy\s*loon",  # Should be ProxyLogon
    r"\b(amazing|incredible|fantastic)\b",  # AI hype words
    r"as an AI",  # AI self-reference leak
    r"I cannot",  # AI refusal leak
    r"CVE[-\s]?\d{4}[-\s]?[XYZ]+",  # Placeholder CVE patterns
    r"CVE[-\s]?XXXX",  # Placeholder year
    r"CVE[-\s]?20\d\d[-\s]?X+",  # Placeholder number
    r"\bversion\s+X\.Y",  # Placeholder version
    r"\bv?\.?\d+\.X\b",  # Placeholder minor version
    r"Michael\s+Shin",  # Known wrong name from bad script
    r"\bSignia\b",  # Misspelling of Sygnia
]

# Known mispronunciation errors (from transcript analysis)
MISPRONUNCIATION_ERRORS = {
    "millin ill": "mail server (ML server)",
    "mera ibo": "Mirai",
    "proxy loon": "ProxyLogon",
    "wellend": "Welltend",
    "altennia": "Oltenia",
    "inex wp": "Innorix WP",
    "gm mission": "G-Mission",
    "moga-mal": "Moga-Mall",
    "pi of": "pair of",
    "gentleman ransomware": "HALLUCINATION - no such group",
}


# =============================================================================
# LAYER 1: RULE-BASED VALIDATION
# =============================================================================

def validate_cve_format(text: str) -> List[Dict]:
    """Check that CVE numbers follow correct format."""
    issues = []

    # Find all CVE references
    cve_pattern = r'CVE[-\s]?(\d{4})[-\s]?(\d+)'
    matches = re.findall(cve_pattern, text, re.IGNORECASE)

    for year, number in matches:
        year = int(year)
        number = int(number)

        # Year should be reasonable (1999-2026)
        if year < 1999 or year > 2026:
            issues.append({
                "type": "invalid_cve",
                "severity": "high",
                "message": f"CVE year {year} seems invalid",
                "value": f"CVE-{year}-{number}"
            })

        # Number shouldn't be impossibly high for the year
        # 2025 shouldn't have CVE numbers above ~60000 yet
        if year == 2025 and number > 60000:
            issues.append({
                "type": "suspicious_cve",
                "severity": "medium",
                "message": f"CVE-{year}-{number} number seems too high for {year}",
                "value": f"CVE-{year}-{number}"
            })

    return issues


def validate_ransomware_groups(text: str) -> List[Dict]:
    """Flag unknown ransomware group names."""
    issues = []

    # Look for "X ransomware" patterns where X is a capitalized proper noun
    # This avoids false positives like "supply chain ransomware" or "the ransomware"
    ransomware_pattern = r'\b([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)?)\s+ransomware\b'
    matches = re.findall(ransomware_pattern, text)

    # Also check for patterns like "ransomware group called X"
    called_pattern = r'(?:ransomware\s+(?:group|gang|actor)s?\s+(?:called|named|known as)\s+)["\']?([A-Za-z0-9]+)["\']?'
    matches.extend(re.findall(called_pattern, text, re.IGNORECASE))

    for group_name in matches:
        normalized = group_name.upper().strip()
        # Skip common false positives
        skip_words = {"THE", "THIS", "THAT", "ANOTHER", "OTHER", "SAME", "NEW"}
        if normalized in skip_words:
            continue
        if normalized not in KNOWN_RANSOMWARE_GROUPS:
            issues.append({
                "type": "unknown_ransomware",
                "severity": "high",
                "message": f"Unknown ransomware group: '{group_name}' - possible hallucination",
                "value": group_name
            })

    return issues


def check_suspicious_patterns(text: str) -> List[Dict]:
    """Flag known hallucination patterns."""
    issues = []

    for pattern in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            issues.append({
                "type": "suspicious_pattern",
                "severity": "high",
                "message": f"Suspicious pattern found: '{matches[0]}'",
                "value": matches[0]
            })

    return issues


def check_mispronunciation_errors(text: str) -> List[Dict]:
    """Flag known mispronunciation errors that slipped through."""
    issues = []
    text_lower = text.lower()

    for error, correction in MISPRONUNCIATION_ERRORS.items():
        if error in text_lower:
            issues.append({
                "type": "mispronunciation",
                "severity": "medium",
                "message": f"Known error '{error}' -> should be '{correction}'",
                "value": error
            })

    return issues


def cross_check_vendors(script: dict, input_data: dict) -> List[Dict]:
    """Verify vendors in script match the input CVE data."""
    issues = []

    # Extract vendors from input data
    input_vendors = set()
    for vuln in input_data.get("vulnerabilities", []):
        vendor = vuln.get("vendor", "").upper()
        product = vuln.get("product", "").upper()
        if vendor:
            input_vendors.add(vendor)
        if product:
            input_vendors.add(product)

    # Extract CVEs mentioned in script
    script_text = " ".join([line.get("text", "") for line in script.get("dialogue", [])])

    # Look for vendor names in script that aren't in input
    # This is a basic check - could be enhanced
    mentioned_cves = re.findall(r'CVE[-\s]?\d{4}[-\s]?\d+', script_text, re.IGNORECASE)

    if mentioned_cves and not input_vendors:
        issues.append({
            "type": "missing_source",
            "severity": "low",
            "message": "Script mentions CVEs but no vendor data provided for cross-check",
            "value": str(mentioned_cves[:3])
        })

    return issues


def cross_check_cves(script: dict, input_data: dict) -> List[Dict]:
    """
    CRITICAL: Verify ALL CVE IDs in script exist in input data.

    This catches LLM hallucination of CVE numbers.
    """
    issues = []

    # Extract CVE IDs from input data
    input_cves = set()
    for vuln in input_data.get("vulnerabilities", []):
        cve_id = vuln.get("cve_id", "")
        if cve_id:
            # Normalize: CVE-2025-12345 -> CVE-2025-12345
            normalized = cve_id.upper().replace(" ", "-")
            input_cves.add(normalized)

    # Also check stories for mentioned CVEs
    for story in input_data.get("stories", []):
        for cve in story.get("mentioned_cves", []):
            normalized = cve.upper().replace(" ", "-")
            input_cves.add(normalized)

    # Extract CVEs mentioned in script
    script_text = " ".join([line.get("text", "") for line in script.get("dialogue", [])])

    # Find all CVE patterns in script
    cve_pattern = r'CVE[-\s]?(\d{4})[-\s]?(\d+)'
    matches = re.findall(cve_pattern, script_text, re.IGNORECASE)

    for year, number in matches:
        script_cve = f"CVE-{year}-{number}"

        # Check if this CVE exists in input
        if script_cve not in input_cves:
            issues.append({
                "type": "hallucinated_cve",
                "severity": "critical",
                "message": f"CVE {script_cve} not found in input data - possible hallucination",
                "value": script_cve
            })

    # Check for placeholder patterns (XXX, YYY, etc.)
    placeholder_pattern = r'CVE[-\s]?\d{4}[-\s]?[XYZ]+|CVE[-\s]?[XYZ]+[-\s]?\d+'
    placeholders = re.findall(placeholder_pattern, script_text, re.IGNORECASE)
    for placeholder in placeholders:
        issues.append({
            "type": "placeholder_cve",
            "severity": "critical",
            "message": f"Placeholder CVE detected: {placeholder} - must use real CVE IDs",
            "value": placeholder
        })

    return issues


def cross_check_story_facts(script: dict, input_data: dict) -> List[Dict]:
    """
    Verify key facts from stories (names, companies) appear in input data.

    This catches LLM invention of names and company misspellings.
    """
    issues = []

    # Build a set of valid names/companies from story data
    valid_terms = set()
    for story in input_data.get("stories", []):
        # Add story title words (company names often in titles)
        title = story.get("title", "")
        # Extract capitalized words (likely proper nouns)
        proper_nouns = re.findall(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', title)
        for noun in proper_nouns:
            valid_terms.add(noun.lower())

        # Add summary proper nouns
        summary = story.get("summary", "")
        proper_nouns = re.findall(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', summary)
        for noun in proper_nouns:
            valid_terms.add(noun.lower())

    # Common words to ignore (not company names)
    ignore_words = {
        "the", "and", "for", "with", "this", "that", "from", "have", "has",
        "been", "were", "was", "are", "but", "not", "they", "their", "what",
        "when", "where", "which", "who", "will", "would", "could", "should",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
        "january", "february", "march", "april", "may", "june", "july",
        "august", "september", "october", "november", "december",
        "security", "cyber", "attack", "breach", "ransomware", "malware",
        "vulnerability", "exploit", "patch", "update", "critical", "high",
        "alec", "melody",  # Host names
    }
    valid_terms -= ignore_words

    # Check script for potential company/person names not in stories
    script_text = " ".join([line.get("text", "") for line in script.get("dialogue", [])])

    # This is a lighter check - we flag if we see patterns that look like
    # invented names (e.g., ransomware groups, company names) that aren't
    # in the input data

    # Check for "X ransomware" where X isn't known
    # Already handled by validate_ransomware_groups

    # Check for "according to X" or "X confirmed" patterns
    attribution_pattern = r'(?:according to|confirmed by|reported by|said)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)'
    attributions = re.findall(attribution_pattern, script_text)

    for name in attributions:
        name_lower = name.lower()
        # Check if it's a known source or in our valid terms
        known_sources = {"bleeping computer", "krebs", "the record", "dark reading",
                        "threatpost", "hacker news", "security week", "schneier",
                        "cisa", "fbi", "nsa", "google", "microsoft", "apple"}
        if name_lower not in known_sources and name_lower not in valid_terms:
            # Check if any part of the name is in valid_terms
            name_parts = name_lower.split()
            if not any(part in valid_terms for part in name_parts):
                issues.append({
                    "type": "unverified_attribution",
                    "severity": "medium",
                    "message": f"Attribution to '{name}' not found in story data - verify source",
                    "value": name
                })

    return issues


def run_rule_based_validation(script: dict, input_data: dict = None) -> List[Dict]:
    """Run all rule-based checks."""

    # Combine all dialogue text
    full_text = " ".join([line.get("text", "") for line in script.get("dialogue", [])])

    all_issues = []

    # Run checks
    all_issues.extend(validate_cve_format(full_text))
    all_issues.extend(validate_ransomware_groups(full_text))
    all_issues.extend(check_suspicious_patterns(full_text))
    all_issues.extend(check_mispronunciation_errors(full_text))

    if input_data:
        all_issues.extend(cross_check_vendors(script, input_data))
        # CRITICAL: Check that CVEs in script exist in input data
        all_issues.extend(cross_check_cves(script, input_data))
        # Check that story facts (names, companies) match input
        all_issues.extend(cross_check_story_facts(script, input_data))

    return all_issues


# =============================================================================
# LAYER 2: LLM VALIDATION
# =============================================================================

# V2: Focused prompt that only checks against source data (not general knowledge)
LLM_VALIDATION_PROMPT_V2 = """You are a fact-checker verifying a cybersecurity podcast script against its source data.

## YOUR ONLY JOB
Verify that claims in the script match the provided SOURCE DATA. You are NOT a security expert - trust the source data as authoritative.

## SOURCE DATA PROVIDED
You will receive:
1. Vulnerability data (CVE IDs, vendors, products, CVSS scores)
2. Story data (headlines, summaries, company names, researcher names)

## WHAT TO CHECK (flag as issues)
1. **CVE IDs** - Flag if script mentions CVE-XXXX-YYYYY that does NOT appear in source data or input data
2. **Statistics** - Flag specific numbers ($8.5 million, 2 million users) that don't appear in source data
3. **CISA KEV status** - Flag if script claims "actively exploited" but source shows cisa_kev=false
4. **Names** - Flag researcher/person names that don't appear in source data

## WHAT NOT TO CHECK (ignore these)
1. **Product names** - If source says "Akuvox S539", trust it's real. Do not flag unfamiliar products.
2. **Company names** - Source data is authoritative. Do not flag because you haven't heard of a company.
3. **Technical accuracy** - Do not verify if the vulnerability description is technically correct.
4. **Writing quality** - Do not flag style issues, just factual mismatches.

## SEVERITY LEVELS
- **critical**: CVE ID in script not found in source data (definite hallucination)
- **high**: Statistics/claims that directly contradict source data
- **medium**: Names or attributions not verifiable against source (may be ok if general)

## OUTPUT FORMAT (JSON only)
{
  "issues_found": true/false,
  "issues": [
    {
      "type": "hallucinated_cve|wrong_statistic|false_claim|unverified_name",
      "severity": "critical|high|medium",
      "script_excerpt": "the problematic text from script",
      "explanation": "why this doesn't match source data",
      "source_check": "what you looked for in source data"
    }
  ],
  "summary": "Brief summary of findings"
}

## SOURCE DATA
{source_data}

## SCRIPT TO VERIFY
{script_text}
"""

# V1: Original prompt (deprecated - flagged legitimate product names as hallucinations)
LLM_VALIDATION_PROMPT = """You are a fact-checker for a cybersecurity podcast script.

Review this script and identify ANY of these issues:

1. HALLUCINATIONS: Made-up company names, fake CVE numbers, non-existent ransomware groups, invented products
2. FACTUAL ERRORS: Wrong CVE details, incorrect severity scores, misattributed vulnerabilities
3. SUSPICIOUS CLAIMS: Extraordinary claims without evidence, unlikely statistics, things that "sound wrong"
4. SPELLING/NAMING: Misspelled vendor names, wrong product names, garbled technical terms

IMPORTANT CONTEXT:
- Real ransomware groups include: LockBit, BlackCat/ALPHV, Clop, Qilin, Akira, Rhysida, Play, Medusa
- CVE format is CVE-YYYY-NNNNN (year-number)
- If you see an unfamiliar ransomware name, FLAG IT

OUTPUT FORMAT (JSON only):
{
  "issues_found": true/false,
  "issues": [
    {
      "type": "hallucination|factual_error|suspicious|spelling",
      "severity": "high|medium|low",
      "line_excerpt": "the problematic text",
      "explanation": "why this is wrong",
      "suggestion": "what it should say (if known)"
    }
  ],
  "confidence": "high|medium|low",
  "summary": "One sentence summary of findings"
}

SCRIPT TO REVIEW:
"""


def run_llm_validation(script: dict) -> Dict:
    """Send script to LLM for hallucination detection."""

    try:
        import google.generativeai as genai
    except ImportError:
        logger.warning("google-generativeai not installed, skipping LLM validation")
        return {"issues_found": False, "issues": [], "error": "LLM not available"}

    config = get_config()
    api_key = config.get("env", {}).get("gemini_api_key")

    if not api_key:
        logger.warning("No Gemini API key, skipping LLM validation")
        return {"issues_found": False, "issues": [], "error": "No API key"}

    # Prepare script text
    dialogue_text = "\n".join([
        f"{line.get('speaker', 'Unknown')}: {line.get('text', '')}"
        for line in script.get("dialogue", [])
    ])

    full_prompt = LLM_VALIDATION_PROMPT + dialogue_text

    try:
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",  # Fast model for validation
            generation_config={
                "temperature": 0.1,  # Low temp for factual checking
                "max_output_tokens": 2000,
            }
        )

        logger.info("Running LLM validation...")
        response = model.generate_content(full_prompt)

        # Parse JSON response
        response_text = response.text.strip()

        # Clean up markdown if present
        if response_text.startswith("```"):
            response_text = re.sub(r'^```json?\n?', '', response_text)
            response_text = re.sub(r'\n?```$', '', response_text)

        result = json.loads(response_text)
        logger.info(f"LLM validation complete: {result.get('summary', 'No summary')}")

        return result

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM response: {e}")
        return {"issues_found": False, "issues": [], "error": f"Parse error: {e}"}
    except Exception as e:
        logger.error(f"LLM validation failed: {e}")
        return {"issues_found": False, "issues": [], "error": str(e)}


# =============================================================================
# SCRIPT FIXER - LLM-based correction
# =============================================================================

FIX_SCRIPT_PROMPT = """You are a script editor fixing errors in a cybersecurity podcast script.

ISSUES FOUND:
{issues}

ORIGINAL SCRIPT:
{script}

TASK:
Fix ALL the issues listed above. Return the COMPLETE corrected script.

RULES:
1. Fix hallucinations by removing or replacing with accurate info
2. Fix spelling errors with correct spelling
3. Fix made-up ransomware groups - use real names (LockBit, Qilin, BlackCat, Clop, Akira) or remove the reference
4. Fix CVE format issues
5. Keep the same dialogue structure (speaker, text format)
6. DO NOT add new content - only fix errors
7. Preserve the natural conversational tone

OUTPUT FORMAT (JSON array only, no markdown):
[
  {{"speaker": "Alec", "text": "corrected text here", "cve_refs": [], "story_refs": []}},
  {{"speaker": "Melody", "text": "corrected text here", "cve_refs": [], "story_refs": []}}
]
"""


def fix_script_issues(script: dict, issues: list) -> dict:
    """
    Send script and issues to LLM to get corrected version.

    Args:
        script: Original script with errors
        issues: List of issues from validation

    Returns:
        Corrected script dict
    """
    try:
        import google.generativeai as genai
    except ImportError:
        logger.error("google-generativeai not installed, cannot fix script")
        return script

    config = get_config()
    api_key = config.get("env", {}).get("gemini_api_key")

    if not api_key:
        logger.error("No Gemini API key, cannot fix script")
        return script

    # Format issues for prompt
    issues_text = "\n".join([
        f"- [{issue.get('severity', 'unknown').upper()}] {issue.get('type', 'unknown')}: {issue.get('message', issue.get('explanation', 'No details'))}"
        for issue in issues
    ])

    # Format script for prompt
    script_text = json.dumps(script.get("dialogue", []), indent=2)

    prompt = FIX_SCRIPT_PROMPT.format(issues=issues_text, script=script_text)

    try:
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",
            generation_config={
                "temperature": 0.3,
                "max_output_tokens": 8000,
            }
        )

        logger.info("Sending script to LLM for fixes...")
        response = model.generate_content(prompt)

        response_text = response.text.strip()

        # Clean up markdown if present
        if response_text.startswith("```"):
            response_text = re.sub(r'^```json?\n?', '', response_text)
            response_text = re.sub(r'\n?```$', '', response_text)

        fixed_dialogue = json.loads(response_text)

        # Rebuild script with fixed dialogue
        fixed_script = script.copy()
        fixed_script["dialogue"] = fixed_dialogue
        fixed_script["fixed_issues"] = len(issues)

        logger.info(f"Script fixed: {len(issues)} issues addressed")
        return fixed_script

    except Exception as e:
        logger.error(f"Failed to fix script: {e}")
        return script


def validate_and_fix(
    script: dict,
    input_data: dict = None,
    max_attempts: int = 2,
    use_llm: bool = True
) -> Tuple[dict, bool, Dict]:
    """
    Validate script and fix issues in a loop.

    Args:
        script: Original script
        input_data: Daily brief for cross-checking
        max_attempts: Max fix attempts before giving up
        use_llm: Whether to use LLM validation

    Returns:
        Tuple of (final_script, passed, report)
    """
    current_script = script
    attempt = 0
    all_reports = []

    while attempt < max_attempts:
        attempt += 1
        logger.info(f"Validation attempt {attempt}/{max_attempts}")

        # Validate
        passed, report = validate_script(
            current_script,
            input_data=input_data,
            use_llm=use_llm,
            fail_on_high=True
        )
        all_reports.append(report)

        blocking_count = report.get("critical_severity_count", 0) + report["high_severity_count"]
        if passed or blocking_count == 0:
            logger.info(f"✅ Script passed validation on attempt {attempt}")
            report["attempts"] = attempt
            return current_script, True, report

        # Collect all blocking issues to fix (critical + high)
        all_issues = report["rule_based_issues"] + report["llm_issues"]
        blocking_issues = [i for i in all_issues if i.get("severity") in ("critical", "high")]

        if not blocking_issues:
            logger.info("No critical/high-severity issues to fix")
            report["attempts"] = attempt
            return current_script, True, report

        logger.info(f"🔧 Fixing {len(blocking_issues)} critical/high-severity issues...")

        # Fix the script
        current_script = fix_script_issues(current_script, blocking_issues)

    # Max attempts reached
    logger.warning(f"⚠️ Max attempts ({max_attempts}) reached, proceeding with warnings")
    final_report = all_reports[-1]
    final_report["attempts"] = attempt
    final_report["max_attempts_reached"] = True

    return current_script, False, final_report


# =============================================================================
# MAIN VALIDATOR
# =============================================================================

def validate_script(
    script: dict,
    input_data: dict = None,
    use_llm: bool = True,
    fail_on_high: bool = True
) -> Tuple[bool, Dict]:
    """
    Run full validation on a script before audio generation.

    Args:
        script: The episode_script.json content
        input_data: Optional daily_brief_packet.json for cross-checking
        use_llm: Whether to run LLM validation (costs API credits)
        fail_on_high: Whether to fail validation on high-severity issues

    Returns:
        Tuple of (passed: bool, report: dict)
    """
    logger.info("=" * 60)
    logger.info("SCRIPT VALIDATION: Pre-flight check")
    logger.info("=" * 60)

    report = {
        "passed": True,
        "rule_based_issues": [],
        "llm_issues": [],
        "total_issues": 0,
        "critical_severity_count": 0,
        "high_severity_count": 0,
        "medium_severity_count": 0,
        "low_severity_count": 0,
    }

    # Layer 1: Rule-based
    logger.info("Layer 1: Rule-based validation...")
    rule_issues = run_rule_based_validation(script, input_data)
    report["rule_based_issues"] = rule_issues

    for issue in rule_issues:
        logger.warning(f"  [{issue['severity'].upper()}] {issue['type']}: {issue['message']}")

    # Layer 2: LLM validation
    if use_llm:
        logger.info("Layer 2: LLM validation...")
        llm_result = run_llm_validation(script)

        if llm_result.get("issues_found"):
            report["llm_issues"] = llm_result.get("issues", [])
            for issue in report["llm_issues"]:
                logger.warning(f"  [LLM-{issue.get('severity', 'unknown').upper()}] {issue.get('type')}: {issue.get('explanation')}")

    # Count severities
    all_issues = report["rule_based_issues"] + report["llm_issues"]
    report["total_issues"] = len(all_issues)

    for issue in all_issues:
        severity = issue.get("severity", "low").lower()
        if severity == "critical":
            report["critical_severity_count"] += 1
        elif severity == "high":
            report["high_severity_count"] += 1
        elif severity == "medium":
            report["medium_severity_count"] += 1
        else:
            report["low_severity_count"] += 1

    # Determine pass/fail - critical OR high severity issues block
    blocking_issues = report["critical_severity_count"] + report["high_severity_count"]
    if fail_on_high and blocking_issues > 0:
        report["passed"] = False
        logger.error(f"VALIDATION FAILED: {report['critical_severity_count']} critical, {report['high_severity_count']} high-severity issues found")
    else:
        logger.info(f"VALIDATION PASSED: {report['total_issues']} issues ({report['critical_severity_count']} critical, {report['high_severity_count']} high)")

    logger.info("=" * 60)

    return report["passed"], report


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        script_path = sys.argv[1]
        with open(script_path) as f:
            script = json.load(f)

        input_data = None
        if len(sys.argv) > 2:
            with open(sys.argv[2]) as f:
                input_data = json.load(f)

        passed, report = validate_script(script, input_data)

        print("\n" + "=" * 60)
        print("VALIDATION REPORT")
        print("=" * 60)
        print(json.dumps(report, indent=2))

        sys.exit(0 if passed else 1)
    else:
        print("Usage: python -m src.pipeline.script_validator <script.json> [input_data.json]")
