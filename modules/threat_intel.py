"""
Dr. SSM Eye - Threat Intelligence Module (Using Cached Feeds)
"""

from typing import Set
from pathlib import Path

from core.data_models import ModuleResult
from core.url_normalizer import normalize_url
from config.settings import (
    DATA_DIR, THREAT_FEED_PHISHTANK_POINTS, THREAT_FEED_URLHAUS_POINTS,
    THREAT_FEED_OPENPHISH_POINTS
)
from utils.logger import logger


class ThreatIntelligence:
    def __init__(self):
        self.urlhaus_cache: Set[str] = set()
        self.openphish_cache: Set[str] = set()
        self.phishtank_cache: Set[str] = set()
        self._load_caches()
    
    def _load_caches(self):
        """Load cached threat feeds from local files"""
        
        # Load URLhaus
        urlhaus_file = DATA_DIR / "urlhaus_cache.txt"
        if urlhaus_file.exists():
            with open(urlhaus_file, 'r', encoding='utf-8') as f:
                self.urlhaus_cache = set(line.strip() for line in f if line.strip())
        
        # Load OpenPhish
        openphish_file = DATA_DIR / "openphish_cache.txt"
        if openphish_file.exists():
            with open(openphish_file, 'r', encoding='utf-8') as f:
                self.openphish_cache = set(line.strip() for line in f if line.strip())
        
        # Load PhishTank
        phishtank_file = DATA_DIR / "phishtank_cache.txt"
        if phishtank_file.exists():
            with open(phishtank_file, 'r', encoding='utf-8') as f:
                self.phishtank_cache = set(line.strip() for line in f if line.strip())
        
        logger.info(f"Loaded threat feeds - URLhaus: {len(self.urlhaus_cache)}, "
                   f"OpenPhish: {len(self.openphish_cache)}, "
                   f"PhishTank: {len(self.phishtank_cache)}")
    
    def check_phishtank(self, url: str) -> bool:
        normalized = normalize_url(url)
        return normalized in self.phishtank_cache or url in self.phishtank_cache
    
    def check_urlhaus(self, url: str) -> bool:
        normalized = normalize_url(url)
        return normalized in self.urlhaus_cache or url in self.urlhaus_cache
    
    def check_openphish(self, url: str) -> bool:
        normalized = normalize_url(url)
        return normalized in self.openphish_cache or url in self.openphish_cache


_threat_intel = None

def get_threat_intel() -> ThreatIntelligence:
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel


def check_threat_feeds(url: str) -> ModuleResult:
    try:
        intel = get_threat_intel()
        
        sources_found = []
        total_points = 0
        
        if intel.check_phishtank(url):
            sources_found.append("PhishTank")
            total_points += THREAT_FEED_PHISHTANK_POINTS
        
        if intel.check_urlhaus(url):
            sources_found.append("URLhaus")
            total_points += THREAT_FEED_URLHAUS_POINTS
        
        if intel.check_openphish(url):
            sources_found.append("OpenPhish")
            total_points += THREAT_FEED_OPENPHISH_POINTS
        
        features = {
            "threat_found": len(sources_found) > 0,
            "sources": sources_found,
            "source_count": len(sources_found)
        }
        
        confidence = 0.95 if sources_found else 0.0
        
        return ModuleResult(
            module_name="threat_intel",
            features=features,
            risk_contribution=total_points,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Threat intelligence check error for {url}: {e}")
        return ModuleResult(
            module_name="threat_intel",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )