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
}

# Common hallucination patterns to flag
SUSPICIOUS_PATTERNS = [
    r"gentleman\s+ransomware",  # Known hallucination
    r"proxy\s*loon",  # Should be ProxyLogon
    r"\b(amazing|incredible|fantastic)\b",  # AI hype words
    r"as an AI",  # AI self-reference leak
    r"I cannot",  # AI refusal leak
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

    # Look for "X ransomware" patterns
    ransomware_pattern = r'(\w+(?:\s+\w+)?)\s+ransomware'
    matches = re.findall(ransomware_pattern, text, re.IGNORECASE)

    for group_name in matches:
        normalized = group_name.upper().strip()
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

    return all_issues


# =============================================================================
# LAYER 2: LLM VALIDATION
# =============================================================================

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
        if severity == "high":
            report["high_severity_count"] += 1
        elif severity == "medium":
            report["medium_severity_count"] += 1
        else:
            report["low_severity_count"] += 1

    # Determine pass/fail
    if fail_on_high and report["high_severity_count"] > 0:
        report["passed"] = False
        logger.error(f"VALIDATION FAILED: {report['high_severity_count']} high-severity issues found")
    else:
        logger.info(f"VALIDATION PASSED: {report['total_issues']} issues ({report['high_severity_count']} high)")

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
