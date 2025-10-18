"""
Dr. SSM Eye - Feature Aggregation Module
"""

from typing import Dict, List, Any
from core.data_models import ModuleResult
from core.url_normalizer import (
    extract_domain, extract_tld, count_subdomains,
    has_ip_address, calculate_url_entropy, get_digit_letter_ratio,
    contains_at_symbol, count_hyphens, extract_port, is_standard_port
)
from config.settings import SUSPICIOUS_TLDS, URL_SHORTENERS
from utils.logger import logger


def aggregate_features(url: str, module_results: List[ModuleResult]) -> Dict[str, Any]:
    try:
        features = {}
        
        domain = extract_domain(url)
        tld = extract_tld(domain)
        
        features["url_length"] = len(url)
        features["subdomain_count"] = count_subdomains(domain)
        features["has_ip_address"] = has_ip_address(url)
        features["has_at_symbol"] = contains_at_symbol(url)
        features["suspicious_tld"] = tld in SUSPICIOUS_TLDS
        features["digit_to_letter_ratio"] = get_digit_letter_ratio(domain)
        features["url_entropy"] = calculate_url_entropy(url)
        features["hyphen_count"] = count_hyphens(domain)
        
        features["contains_brand_name"] = False
        features["uses_url_shortener"] = any(shortener in domain for shortener in URL_SHORTENERS)
        
        port = extract_port(url)
        scheme = "https" if "https" in url else "http"
        features["non_standard_port"] = not is_standard_port(port, scheme)
        
        for result in module_results:
            if result.module_name == "whois_check":
                features["domain_age_days"] = result.features.get("domain_age_days")
                features["certificate_age_days"] = None
            
            elif result.module_name == "whitelist_check":
                features["in_tranco_top_10k"] = result.features.get("whitelist_tier") == "top_10k"
            
            elif result.module_name == "threat_intel":
                features["in_threat_database"] = result.features.get("threat_found", False)
            
            elif result.module_name == "ssl_check":
                features["has_https"] = result.features.get("has_https", False)
                features["certificate_age_days"] = result.features.get("certificate_age_days")
            
            elif result.module_name == "dns_check":
                features["response_time_ms"] = int(result.features.get("response_time", 0) * 1000)
            
            elif result.module_name == "content_check":
                features["has_password_field"] = result.features.get("has_password_field", False)
                features["external_resource_count"] = result.features.get("external_resources", 0)
                page_title = result.features.get("page_title", "")
                features["page_title_brand_match"] = False
            
            elif result.module_name == "brand_check":
                brand_detected = result.features.get("brand_detected")
                if brand_detected:
                    features["contains_brand_name"] = True
            
            elif result.module_name == "favicon_match":
                features["favicon_domain_match"] = result.features.get("matched_brand") is not None
            
            elif result.module_name == "redirect_check":
                features["subdomain_pattern_suspicious"] = False
        
        features["tld_reputation_score"] = -10 if not features["suspicious_tld"] else 10
        
        return features
        
    except Exception as e:
        logger.error(f"Feature aggregation error: {e}")
        return {}