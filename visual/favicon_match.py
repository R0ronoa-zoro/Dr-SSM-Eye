"""
Dr. SSM Eye - Favicon Matching Module
"""

import requests
import imagehash
from PIL import Image
import io
from typing import Optional, Tuple

from core.data_models import ModuleResult
from core.url_normalizer import extract_domain
from config.settings import (
    HTTP_REQUEST_TIMEOUT, MIN_FAVICON_MATCH_DISTANCE,
    FAVICON_EXACT_MATCH_DISTANCE, FAVICON_SIMILAR_MATCH_DISTANCE,
    BRANDS_JSON_PATH, BRAND_FAVICON_MATCH_POINTS
)
from utils.logger import logger
from utils.helpers import load_json_file


def compute_favicon_hash(favicon_bytes: bytes) -> Optional[str]:
    try:
        image = Image.open(io.BytesIO(favicon_bytes))
        
        phash = imagehash.average_hash(image)
        
        return str(phash)
        
    except Exception as e:
        logger.warning(f"Favicon hash computation error: {e}")
        return None


def download_favicon(url: str) -> Optional[bytes]:
    domain = extract_domain(url)
    
    favicon_urls = [
        f"https://{domain}/favicon.ico",
        f"https://{domain}/apple-touch-icon.png",
        f"https://www.google.com/s2/favicons?domain={domain}&sz=128"
    ]
    
    for favicon_url in favicon_urls:
        try:
            response = requests.get(favicon_url, timeout=HTTP_REQUEST_TIMEOUT)
            if response.status_code == 200 and len(response.content) > 0:
                return response.content
        except:
            continue
    
    return None


def extract_and_match_favicon(url: str) -> ModuleResult:
    try:
        favicon_bytes = download_favicon(url)
        
        if not favicon_bytes:
            return ModuleResult(
                module_name="favicon_match",
                features={"favicon_downloaded": False},
                risk_contribution=0,
                confidence=0.0
            )
        
        favicon_hash = compute_favicon_hash(favicon_bytes)
        
        if not favicon_hash:
            return ModuleResult(
                module_name="favicon_match",
                features={"favicon_hash_computed": False},
                risk_contribution=0,
                confidence=0.0
            )
        
        features = {
            "favicon_hash": favicon_hash,
            "matched_brand": None,
            "hash_distance": None,
            "match_quality": None
        }
        
        risk_contribution = 0
        
        brands_data = load_json_file(str(BRANDS_JSON_PATH))
        
        if not brands_data or 'brands' not in brands_data:
            return ModuleResult(
                module_name="favicon_match",
                features=features,
                risk_contribution=0,
                confidence=0.5
            )
        
        best_match_brand = None
        best_distance = float('inf')
        
        for brand in brands_data.get('brands', []):
            brand_favicon_hash = brand.get('favicon_hash')
            
            if not brand_favicon_hash:
                continue
            
            try:
                brand_hash = imagehash.hex_to_hash(brand_favicon_hash)
                current_hash = imagehash.hex_to_hash(favicon_hash)
                
                distance = brand_hash - current_hash
                
                if distance < best_distance:
                    best_distance = distance
                    best_match_brand = brand['name']
                    
            except:
                continue
        
        if best_distance <= MIN_FAVICON_MATCH_DISTANCE:
            features["matched_brand"] = best_match_brand
            features["hash_distance"] = int(best_distance)
            
            if best_distance <= FAVICON_EXACT_MATCH_DISTANCE:
                features["match_quality"] = "exact"
                risk_contribution += BRAND_FAVICON_MATCH_POINTS
            elif best_distance <= FAVICON_SIMILAR_MATCH_DISTANCE:
                features["match_quality"] = "similar"
                risk_contribution += int(BRAND_FAVICON_MATCH_POINTS * 0.6)
        
        confidence = 0.85 if features["matched_brand"] else 0.5
        
        return ModuleResult(
            module_name="favicon_match",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Favicon match error for {url}: {e}")
        return ModuleResult(
            module_name="favicon_match",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )