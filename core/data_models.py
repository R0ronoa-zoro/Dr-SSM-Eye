"""
Dr. SSM Eye - Data Models
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum


class Classification(Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    ANALYST_REQUIRED = "ANALYST_REQUIRED"
    UNDEFINED = "UNDEFINED"


class ScreenshotStatus(Enum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"


class ImpactType(Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


@dataclass
class Reason:
    feature: str
    value: Any
    points: int
    impact: str
    description: str


@dataclass
class ModuleResult:
    module_name: str
    features: Dict[str, Any]
    risk_contribution: int
    confidence: float
    error: Optional[str] = None
    execution_time_ms: int = 0


@dataclass
class RedirectHop:
    hop_number: int
    url: str
    status_code: int
    timestamp: datetime


@dataclass
class ScanResult:
    url: str
    normalized_url: str
    classification: str
    confidence: float
    risk_score: int
    reasoning: List[Reason]
    features: Dict[str, Any]
    screenshot_status: str
    screenshot_paths: Dict[str, str]
    timestamp: datetime
    scan_duration: float
    source_url: Optional[str] = None
    dest_url: Optional[str] = None
    brand_detected: Optional[str] = None
    impersonation_score: Optional[int] = None
    ip_address: Optional[str] = None
    asn: Optional[int] = None
    domain_age_days: Optional[int] = None
    module_results: List[ModuleResult] = field(default_factory=list)


@dataclass
class BrandInfo:
    id: str
    name: str
    region: str
    category: str
    domains: List[str]
    favicon_hash: str
    logo_hash: str
    common_typos: List[str]
    keywords: List[str]
    verified: bool
    last_updated: str


@dataclass
class ThreatFeedEntry:
    url: str
    source: str
    threat_type: str
    first_seen: datetime
    last_seen: datetime
    confidence: int


@dataclass
class IPReputationEntry:
    ip_address: str
    asn: Optional[int]
    asn_name: Optional[str]
    country: Optional[str]
    first_seen: datetime
    last_seen: datetime
    threat_type: str
    confidence: int
    source: str
    notes: Optional[str] = None


@dataclass
class ScreenshotMetadata:
    url_hash: str
    thumbnail_hash: str
    full_hash: str
    thumbnail_path: str
    full_path: str
    captured_at: datetime
    file_size_bytes: int


@dataclass
class AnalystReview:
    url: str
    original_classification: str
    analyst_verdict: str
    analyst_notes: str
    reviewed_at: datetime
    reviewed_by: str