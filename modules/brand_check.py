"""
Brand Verification Module
Checks for brand impersonation
"""

import logging
import json
from typing import Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse

from core.data_models import ModuleResult

logger = logging.getLogger('dr_ssm_eye')


def load_brands() -> list:
    """Load brands database"""
    try:
        brands_path = Path("data/brands.json")
        if brands_path.exists():
            with open(brands_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('brands', [])
        return []
    except Exception as e:
        logger.error(f"Error loading brands: {e}")
        return []


def check_brand_impersonation(
    url: str,
    content: str = "",
    favicon: bytes = None,
    screenshot: str = ""
) -> ModuleResult:
    """
    Check for brand impersonation
    
    Args:
        url: URL to check
        content: Page content/title
        favicon: Favicon bytes
        screenshot: Screenshot path
    
    Returns:
        ModuleResult with brand detection info
    """
    try:
        brands = load_brands()
        
        if not brands:
            return ModuleResult(
                module_name="brand_check",
                features={
                    "brand_detected": None,
                    "is_official_domain": False,
                    "impersonation_type": "none"
                },
                risk_contribution=0,
                confidence=0.0
            )
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        
        for brand in brands:
            brand_domains = [d.lower() for d in brand.get('domains', [])]
            
            if domain in brand_domains:
                return ModuleResult(
                    module_name="brand_check",
                    features={
                        "brand_detected": brand['name'],
                        "is_official_domain": True,
                        "impersonation_type": "none",
                        "evidence": {}
                    },
                    risk_contribution=-40,
                    confidence=1.0
                )
        
        for brand in brands:
            brand_name = brand['name'].lower()
            brand_keywords = [k.lower() for k in brand.get('keywords', [])]
            
            if any(keyword in domain for keyword in brand_keywords):
                return ModuleResult(
                    module_name="brand_check",
                    features={
                        "brand_detected": brand['name'],
                        "is_official_domain": False,
                        "impersonation_type": "domain_similarity",
                        "evidence": {
                            "domain_contains_brand": True
                        }
                    },
                    risk_contribution=25,
                    confidence=0.7
                )
            
            if content and brand_name in content.lower():
                return ModuleResult(
                    module_name="brand_check",
                    features={
                        "brand_detected": brand['name'],
                        "is_official_domain": False,
                        "impersonation_type": "content_mention",
                        "evidence": {
                            "brand_in_content": True
                        }
                    },
                    risk_contribution=10,
                    confidence=0.5
                )
        
        return ModuleResult(
            module_name="brand_check",
            features={
                "brand_detected": None,
                "is_official_domain": False,
                "impersonation_type": "none",
                "evidence": {}
            },
            risk_contribution=0,
            confidence=0.0
        )
    
    except Exception as e:
        logger.error(f"Brand check error: {e}")
        return ModuleResult(
            module_name="brand_check",
            features={
                "error": str(e),
                "brand_detected": None,
                "is_official_domain": False,
                "impersonation_type": "none"
            },
            risk_contribution=0,
            confidence=0.0
        )