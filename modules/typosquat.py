"""
Dr. SSM Eye - Typosquatting Detection Module
"""

import difflib
from typing import Optional, Tuple
import unicodedata

from core.data_models import ModuleResult
from core.url_normalizer import extract_domain, extract_base_domain
from config.settings import (
    BRANDS_JSON_PATH, TYPOSQUAT_HIGH_SIMILARITY, TYPOSQUAT_MEDIUM_SIMILARITY,
    TYPOSQUAT_LOW_SIMILARITY, TYPOSQUAT_HIGH_POINTS, TYPOSQUAT_MEDIUM_POINTS,
    TYPOSQUAT_LOW_POINTS
)
from utils.logger import logger
from utils.helpers import load_json_file


def detect_homographs(domain: str) -> bool:
    try:
        normalized = unicodedata.normalize('NFKC', domain)
        
        for char in normalized:
            if ord(char) > 127:
                script = unicodedata.name(char, '').split()[0]
                if script in ['CYRILLIC', 'GREEK']:
                    return True
        
        ascii_domain = domain.encode('ascii', 'ignore').decode('ascii')
        if len(ascii_domain) != len(domain):
            return True
            
    except:
        pass
    
    return False


def calculate_similarity(str1: str, str2: str) -> float:
    if not str1 or not str2:
        return 0.0
    
    return difflib.SequenceMatcher(None, str1.lower(), str2.lower()).ratio()


def check_character_substitution(domain: str, brand: str) -> Tuple[bool, str]:
    substitutions = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', '!', 'l'],
        'o': ['0'],
        's': ['5', '$'],
        'l': ['1', 'i'],
        't': ['7']
    }
    
    domain_lower = domain.lower()
    brand_lower = brand.lower()
    
    for original, subs in substitutions.items():
        for sub in subs:
            test_domain = domain_lower.replace(sub, original)
            if test_domain == brand_lower:
                return True, f"{sub}→{original}"
    
    return False, ""


def detect_typosquatting(url: str) -> ModuleResult:
    try:
        domain = extract_domain(url)
        base_domain = extract_base_domain(domain)
        
        domain_name = base_domain.split('.')[0] if '.' in base_domain else base_domain
        
        features = {
            "is_typosquat": False,
            "target_brand": None,
            "similarity": 0.0,
            "technique": None,
            "original": None,
            "typo": domain_name,
            "has_homographs": False
        }
        
        risk_contribution = 0
        
        has_homographs = detect_homographs(domain)
        features["has_homographs"] = has_homographs
        
        if has_homographs:
            features["is_typosquat"] = True
            features["technique"] = "homograph_attack"
            risk_contribution += TYPOSQUAT_HIGH_POINTS
        
        brands_data = load_json_file(str(BRANDS_JSON_PATH))
        
        if not brands_data or 'brands' not in brands_data:
            logger.warning("Brand database not found or empty")
            return ModuleResult(
                module_name="typosquat",
                features=features,
                risk_contribution=risk_contribution,
                confidence=0.0
            )
        
        best_match_brand = None
        best_similarity = 0.0
        best_technique = None
        
        for brand in brands_data.get('brands', []):
            brand_domains = brand.get('domains', [])
            brand_typos = brand.get('common_typos', [])
            
            for brand_domain in brand_domains:
                brand_name = brand_domain.split('.')[0]
                
                if domain_name == brand_name:
                    continue
                
                similarity = calculate_similarity(domain_name, brand_name)
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match_brand = brand['name']
                    best_technique = "similarity_match"
                    features["original"] = brand_name
                
                is_sub, sub_type = check_character_substitution(domain_name, brand_name)
                if is_sub:
                    best_similarity = 0.95
                    best_match_brand = brand['name']
                    best_technique = f"character_substitution_{sub_type}"
                    features["original"] = brand_name
                    break
            
            if domain_name in brand_typos:
                best_similarity = 1.0
                best_match_brand = brand['name']
                best_technique = "known_typo"
                features["original"] = brand_domains[0].split('.')[0] if brand_domains else ""
                break
        
        if best_similarity >= TYPOSQUAT_LOW_SIMILARITY:
            features["is_typosquat"] = True
            features["target_brand"] = best_match_brand
            features["similarity"] = round(best_similarity, 2)
            features["technique"] = best_technique
            
            if best_similarity >= TYPOSQUAT_HIGH_SIMILARITY:
                risk_contribution += TYPOSQUAT_HIGH_POINTS
            elif best_similarity >= TYPOSQUAT_MEDIUM_SIMILARITY:
                risk_contribution += TYPOSQUAT_MEDIUM_POINTS
            else:
                risk_contribution += TYPOSQUAT_LOW_POINTS
        
        confidence = 0.85 if features["is_typosquat"] else 0.5
        
        return ModuleResult(
            module_name="typosquat",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Typosquatting detection error for {url}: {e}")
        return ModuleResult(
            module_name="typosquat",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )
