"""
Story Impact Scoring.

Calculates relevance scores for news stories based on impact indicators.
"""

import re
from typing import List

from .models import Story, StoryType
from ..pipeline.vendor_tiers import TIER_1, TIER_2


def calculate_impact_score(story: Story) -> float:
    """
    Calculate impact score based on story indicators.

    Factors:
    - Dollar amounts (millions/billions)
    - User counts (millions affected)
    - Tier 1/2 vendor mentions
    - Nation-state/APT attribution
    - Supply chain implications
    - Government/critical infrastructure

    Returns:
        Score 0-100
    """
    score = 0.0
    text = f"{story.title} {story.summary}".upper()

    # Dollar amounts (millions+)
    money_patterns = [
        (r'\$\d+(?:\.\d+)?\s*(?:MILLION|M\b)', 30),   # $X million
        (r'\$\d+(?:\.\d+)?\s*(?:BILLION|B\b)', 50),   # $X billion
        (r'MILLIONS?\s+(?:OF\s+)?(?:DOLLARS|USD)', 25),
    ]
    for pattern, points in money_patterns:
        if re.search(pattern, text):
            score += points
            break  # Only count once

    # User counts
    user_patterns = [
        (r'(?:MILLIONS?\s+(?:OF\s+)?(?:\w+\s+)*USERS?|OVER\s+\d+\s*M(?:ILLION)?\s+USERS?)', 25),
        (r'(?:THOUSANDS?\s+(?:OF\s+)?(?:\w+\s+)*USERS?|OVER\s+\d+K?\s+USERS?)', 10),
        (r'WIDESPREAD|MASSIVE|GLOBAL', 15),
    ]
    for pattern, points in user_patterns:
        if re.search(pattern, text):
            score += points
            break

    # Tier 1 vendor mentions
    tier1_found = False
    for vendor in TIER_1:
        if vendor in text:
            score += 20
            tier1_found = True
            break

    # Tier 2 vendor mentions (smaller boost)
    if not tier1_found:  # Only if no Tier 1 found
        for vendor in TIER_2:
            if vendor in text:
                score += 10
                break

    # Nation-state / APT attribution
    apt_patterns = [
        r'(?:CHINA|RUSSIA|IRAN|NORTH KOREA)[\s-]?(?:LINKED|NEXUS|BACKED|SPONSORED)',
        r'APT\d+',
        r'NATION[\s-]?STATE',
        r'(?:VOLT\s*TYPHOON|FANCY\s*BEAR|COZY\s*BEAR|LAZARUS)',
    ]
    for pattern in apt_patterns:
        if re.search(pattern, text):
            score += 25
            break

    # Supply chain
    if re.search(r'SUPPLY\s*CHAIN', text):
        score += 15

    # Government / Critical Infrastructure
    gov_patterns = [
        r'(?:GOVERNMENT|FEDERAL|STATE\s+AGENCY)',
        r'CRITICAL\s+INFRASTRUCTURE',
        r'(?:HOSPITAL|HEALTHCARE|POWER\s+GRID|WATER\s+UTILITY)',
    ]
    for pattern in gov_patterns:
        if re.search(pattern, text):
            score += 20
            break

    # Story type boosts
    type_boosts = {
        StoryType.BREACH: 10,
        StoryType.RANSOMWARE: 10,
        StoryType.APT: 15,
    }
    score += type_boosts.get(story.story_type, 0)

    # Cap at 100
    return min(score, 100.0)


def rank_stories_by_impact(stories: List[Story]) -> List[Story]:
    """
    Rank stories by impact score.

    Updates each story's impact_score and re-calculates final_score.

    Returns:
        Stories sorted by final_score descending
    """
    for story in stories:
        story.impact_score = calculate_impact_score(story)
        story.calculate_final_score()

    return sorted(stories, key=lambda s: s.final_score, reverse=True)
