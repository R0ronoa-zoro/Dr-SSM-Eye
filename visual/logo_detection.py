"""
Dr. SSM Eye - Logo Detection Module
"""

import cv2
import numpy as np
from typing import Optional, Tuple

from core.data_models import ModuleResult
from config.settings import (
    MIN_LOGO_CONFIDENCE, LOGO_HEADER_Y_THRESHOLD,
    LOGO_FOOTER_Y_THRESHOLD, LOGO_PRIMARY_SIZE_THRESHOLD,
    LOGO_SMALL_SIZE_THRESHOLD, BRAND_LOGO_HEADER_POINTS,
    BRAND_LOGO_FOOTER_POINTS, BRAND_LOGOS_PATH
)
from utils.logger import logger


def detect_logo(screenshot_bytes: bytes, brand: str) -> ModuleResult:
    try:
        logo_path = BRAND_LOGOS_PATH / f"{brand.lower().replace(' ', '_')}.png"
        
        if not logo_path.exists():
            return ModuleResult(
                module_name="logo_detection",
                features={"logo_template_not_found": True},
                risk_contribution=0,
                confidence=0.0
            )
        
        screenshot_array = np.frombuffer(screenshot_bytes, np.uint8)
        screenshot_img = cv2.imdecode(screenshot_array, cv2.IMREAD_COLOR)
        
        logo_img = cv2.imread(str(logo_path), cv2.IMREAD_COLOR)
        
        if screenshot_img is None or logo_img is None:
            return ModuleResult(
                module_name="logo_detection",
                features={"image_load_failed": True},
                risk_contribution=0,
                confidence=0.0
            )
        
        result = cv2.matchTemplate(screenshot_img, logo_img, cv2.TM_CCOEFF_NORMED)
        
        min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
        
        features = {
            "logo_detected": False,
            "position": None,
            "confidence": float(max_val),
            "bounding_box": None
        }
        
        risk_contribution = 0
        
        if max_val >= MIN_LOGO_CONFIDENCE:
            features["logo_detected"] = True
            
            logo_h, logo_w = logo_img.shape[:2]
            top_left = max_loc
            bottom_right = (top_left[0] + logo_w, top_left[1] + logo_h)
            
            features["bounding_box"] = {
                "x": top_left[0],
                "y": top_left[1],
                "width": logo_w,
                "height": logo_h
            }
            
            y_position = top_left[1]
            
            if y_position < LOGO_HEADER_Y_THRESHOLD:
                features["position"] = "header"
                risk_contribution += BRAND_LOGO_HEADER_POINTS
            elif y_position > LOGO_FOOTER_Y_THRESHOLD:
                features["position"] = "footer"
                risk_contribution += BRAND_LOGO_FOOTER_POINTS
            else:
                features["position"] = "middle"
                risk_contribution += int((BRAND_LOGO_HEADER_POINTS + BRAND_LOGO_FOOTER_POINTS) / 2)
        
        confidence = max_val if features["logo_detected"] else 0.0
        
        return ModuleResult(
            module_name="logo_detection",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Logo detection error: {e}")
        return ModuleResult(
            module_name="logo_detection",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )