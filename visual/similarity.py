"""
Dr. SSM Eye - Visual Similarity Module
"""

import imagehash
from PIL import Image
import io
from typing import Optional

from core.data_models import ModuleResult
from config.settings import (
    MIN_VISUAL_SIMILARITY, HIGH_VISUAL_SIMILARITY,
    MODERATE_VISUAL_SIMILARITY, BRAND_LAYOUT_SIMILAR_POINTS,
    BRAND_SCREENSHOTS_PATH
)
from utils.logger import logger


def calculate_visual_similarity(screenshot1_bytes: bytes, screenshot2_bytes: bytes) -> float:
    try:
        image1 = Image.open(io.BytesIO(screenshot1_bytes))
        image2 = Image.open(io.BytesIO(screenshot2_bytes))
        
        hash1 = imagehash.phash(image1)
        hash2 = imagehash.phash(image2)
        
        hamming_distance = hash1 - hash2
        
        max_distance = 64
        similarity = 1.0 - (hamming_distance / max_distance)
        
        return similarity
        
    except Exception as e:
        logger.error(f"Visual similarity calculation error: {e}")
        return 0.0


def compare_with_brand_screenshot(url_screenshot_bytes: bytes, brand: str) -> ModuleResult:
    try:
        brand_screenshot_path = BRAND_SCREENSHOTS_PATH / f"{brand.lower().replace(' ', '_')}.png"
        
        if not brand_screenshot_path.exists():
            return ModuleResult(
                module_name="visual_similarity",
                features={"brand_screenshot_not_found": True},
                risk_contribution=0,
                confidence=0.0
            )
        
        with open(brand_screenshot_path, 'rb') as f:
            brand_screenshot_bytes = f.read()
        
        similarity = calculate_visual_similarity(url_screenshot_bytes, brand_screenshot_bytes)
        
        features = {
            "similarity": round(similarity, 2),
            "brand": brand,
            "similarity_level": None
        }
        
        risk_contribution = 0
        
        if similarity >= HIGH_VISUAL_SIMILARITY:
            features["similarity_level"] = "very_high"
            risk_contribution += BRAND_LAYOUT_SIMILAR_POINTS
        elif similarity >= MIN_VISUAL_SIMILARITY:
            features["similarity_level"] = "high"
            risk_contribution += int(BRAND_LAYOUT_SIMILAR_POINTS * 0.8)
        elif similarity >= MODERATE_VISUAL_SIMILARITY:
            features["similarity_level"] = "moderate"
            risk_contribution += int(BRAND_LAYOUT_SIMILAR_POINTS * 0.4)
        else:
            features["similarity_level"] = "low"
        
        confidence = 0.8 if similarity >= MIN_VISUAL_SIMILARITY else 0.5
        
        return ModuleResult(
            module_name="visual_similarity",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Brand screenshot comparison error: {e}")
        return ModuleResult(
            module_name="visual_similarity",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )