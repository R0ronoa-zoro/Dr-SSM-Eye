"""
Dr. SSM Eye - Whitelist Check Module
"""

from typing import Set, Optional
from pathlib import Path
import csv

from core.data_models import ModuleResult
from core.url_normalizer import extract_domain
from config.settings import (
    TRANCO_CACHE_PATH, TRANCO_TOP_10K, TRANCO_TOP_100K,
    WHITELIST_TOP_10K_POINTS, WHITELIST_TOP_100K_POINTS, WHITELIST_TOP_1M_POINTS
)
from utils.logger import logger


class TrancoWhitelist:
    def __init__(self):
        self.top_10k: Set[str] = set()
        self.top_100k: Set[str] = set()
        self.top_1m: Set[str] = set()
        self._load_tranco()
    
    def _load_tranco(self):
        try:
            if not TRANCO_CACHE_PATH.exists():
                logger.warning(f"Tranco list not found at {TRANCO_CACHE_PATH}")
                return
            
            with open(TRANCO_CACHE_PATH, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for i, row in enumerate(reader, 1):
                    if len(row) >= 2:
                        domain = row[1].strip().lower()
                        
                        if i <= TRANCO_TOP_10K:
                            self.top_10k.add(domain)
                        if i <= TRANCO_TOP_100K:
                            self.top_100k.add(domain)
                        
                        self.top_1m.add(domain)
            
            logger.info(f"Loaded Tranco whitelist: {len(self.top_10k)} top 10K, {len(self.top_100k)} top 100K")
            
        except Exception as e:
            logger.error(f"Error loading Tranco list: {e}")
    
    def check_domain(self, domain: str) -> tuple[Optional[int], str]:
        domain = domain.lower()
        
        if domain in self.top_10k:
            rank = list(self.top_10k).index(domain) + 1
            return rank, "top_10k"
        elif domain in self.top_100k:
            rank = list(self.top_100k).index(domain) + 1
            return rank, "top_100k"
        elif domain in self.top_1m:
            return None, "top_1m"
        
        return None, "not_found"


_whitelist = None

def get_whitelist() -> TrancoWhitelist:
    global _whitelist
    if _whitelist is None:
        _whitelist = TrancoWhitelist()
    return _whitelist


def check_whitelist(url: str) -> ModuleResult:
    try:
        domain = extract_domain(url)
        whitelist = get_whitelist()
        
        rank, tier = whitelist.check_domain(domain)
        
        if tier == "top_10k":
            risk_contribution = WHITELIST_TOP_10K_POINTS
            confidence = 0.99
        elif tier == "top_100k":
            risk_contribution = WHITELIST_TOP_100K_POINTS
            confidence = 0.95
        elif tier == "top_1m":
            risk_contribution = WHITELIST_TOP_1M_POINTS
            confidence = 0.85
        else:
            risk_contribution = 0
            confidence = 0.0
        
        features = {
            "in_whitelist": tier != "not_found",
            "whitelist_tier": tier,
            "tranco_rank": rank
        }
        
        return ModuleResult(
            module_name="whitelist_check",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Whitelist check error for {url}: {e}")
        return ModuleResult(
            module_name="whitelist_check",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )