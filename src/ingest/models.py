"""
Data models for vulnerability and news ingestion.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List


class Priority(Enum):
    """Vulnerability priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    FILTERED = "FILTERED"


class StoryType(Enum):
    """Types of security news stories."""
    BREACH = "breach"
    THREAT_INTEL = "threat_intel"
    INDUSTRY = "industry"
    VULNERABILITY = "vulnerability"
    RANSOMWARE = "ransomware"
    APT = "apt"
    GENERAL = "general"


@dataclass
class Story:
    """
    Represents a security news story from RSS/social sources.

    Used alongside Vulnerability for general cybersecurity news coverage.
    """
    # Core identifiers
    id: str  # Hash of URL for deduplication
    title: str
    summary: str = ""
    url: str = ""

    # Classification
    story_type: StoryType = StoryType.GENERAL

    # Scoring components (0-100 scale each, weighted to final score)
    recency_score: float = 0.0    # 30% weight - how recent
    impact_score: float = 0.0     # 40% weight - severity/reach
    buzz_score: float = 0.0       # 30% weight - social engagement
    final_score: float = 0.0      # Weighted combination

    # Metadata
    source: str = ""              # e.g., "bleepingcomputer", "krebsonsecurity"
    source_name: str = ""         # Human-readable: "BleepingComputer"
    author: str = ""
    published_date: Optional[datetime] = None
    fetched_at: Optional[datetime] = None

    # Content signals
    tags: List[str] = field(default_factory=list)
    mentioned_cves: List[str] = field(default_factory=list)  # CVE IDs found in content
    mentioned_vendors: List[str] = field(default_factory=list)

    # Engagement metrics (for buzz scoring)
    social_shares: int = 0
    reddit_score: int = 0

    def calculate_final_score(self) -> float:
        """Calculate weighted final score."""
        self.final_score = (
            self.recency_score * 0.30 +
            self.impact_score * 0.40 +
            self.buzz_score * 0.30
        )
        return self.final_score

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "url": self.url,
            "story_type": self.story_type.value,
            "recency_score": self.recency_score,
            "impact_score": self.impact_score,
            "buzz_score": self.buzz_score,
            "final_score": self.final_score,
            "source": self.source,
            "source_name": self.source_name,
            "author": self.author,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "tags": self.tags,
            "mentioned_cves": self.mentioned_cves,
            "mentioned_vendors": self.mentioned_vendors,
            "social_shares": self.social_shares,
            "reddit_score": self.reddit_score,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Story":
        """Create from dictionary."""
        published = None
        if data.get("published_date"):
            published = datetime.fromisoformat(data["published_date"])

        fetched = None
        if data.get("fetched_at"):
            fetched = datetime.fromisoformat(data["fetched_at"])

        story_type = StoryType.GENERAL
        if data.get("story_type"):
            story_type = StoryType(data["story_type"])

        return cls(
            id=data["id"],
            title=data["title"],
            summary=data.get("summary", ""),
            url=data.get("url", ""),
            story_type=story_type,
            recency_score=data.get("recency_score", 0.0),
            impact_score=data.get("impact_score", 0.0),
            buzz_score=data.get("buzz_score", 0.0),
            final_score=data.get("final_score", 0.0),
            source=data.get("source", ""),
            source_name=data.get("source_name", ""),
            author=data.get("author", ""),
            published_date=published,
            fetched_at=fetched,
            tags=data.get("tags", []),
            mentioned_cves=data.get("mentioned_cves", []),
            mentioned_vendors=data.get("mentioned_vendors", []),
            social_shares=data.get("social_shares", 0),
            reddit_score=data.get("reddit_score", 0),
        )


@dataclass
class Vulnerability:
    """
    Represents a single vulnerability with all associated data.

    This is the core data structure that flows through the pipeline.
    """
    # Core identifiers
    cve_id: str
    title: str = ""
    description: str = ""

    # Scoring
    cvss_score: float = 0.0
    cvss_vector: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0

    # Classification
    cisa_kev: bool = False
    kev_due_date: Optional[str] = None
    priority: Optional[Priority] = None

    # Affected software
    vendor: str = ""
    product: str = ""
    affected_versions: str = ""
    fixed_version: str = ""

    # Remediation
    remediation_url: str = ""
    references: List[str] = field(default_factory=list)

    # Exploit status
    exploit_status: str = "none"  # none, poc_public, actively_exploited

    # Generated content
    bluf: str = ""  # Bottom Line Up Front - set by LLM

    # Metadata
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    source: str = "NVD"

    # Internal tracking
    _is_fallback: bool = False  # True if included via minimum content guarantee

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "cisa_kev": self.cisa_kev,
            "kev_due_date": self.kev_due_date,
            "priority": self.priority.value if self.priority else None,
            "vendor": self.vendor,
            "product": self.product,
            "affected_versions": self.affected_versions,
            "fixed_version": self.fixed_version,
            "remediation_url": self.remediation_url,
            "references": self.references,
            "exploit_status": self.exploit_status,
            "bluf": self.bluf,
            "published_date": self.published_date,
            "last_modified": self.last_modified,
            "source": self.source,
            "_is_fallback": self._is_fallback,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Vulnerability":
        """Create from dictionary."""
        priority = None
        if data.get("priority"):
            priority = Priority(data["priority"])

        return cls(
            cve_id=data["cve_id"],
            title=data.get("title", ""),
            description=data.get("description", ""),
            cvss_score=data.get("cvss_score", 0.0),
            cvss_vector=data.get("cvss_vector", ""),
            epss_score=data.get("epss_score", 0.0),
            epss_percentile=data.get("epss_percentile", 0.0),
            cisa_kev=data.get("cisa_kev", False),
            kev_due_date=data.get("kev_due_date"),
            priority=priority,
            vendor=data.get("vendor", ""),
            product=data.get("product", ""),
            affected_versions=data.get("affected_versions", ""),
            fixed_version=data.get("fixed_version", ""),
            remediation_url=data.get("remediation_url", ""),
            references=data.get("references", []),
            exploit_status=data.get("exploit_status", "none"),
            bluf=data.get("bluf", ""),
            published_date=data.get("published_date"),
            last_modified=data.get("last_modified"),
            source=data.get("source", "NVD"),
            _is_fallback=data.get("_is_fallback", False),
        )
