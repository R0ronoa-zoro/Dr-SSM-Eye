"""
Dr. SSM Eye - Generate Asset Hashes
Script to compute perceptual hashes for brand assets
"""

import json
from pathlib import Path
from PIL import Image
import imagehash

from config.settings import (
    BRANDS_JSON_PATH, BRAND_FAVICONS_PATH,
    BRAND_LOGOS_PATH, BRAND_SCREENSHOTS_PATH
)
from utils.logger import logger


def compute_image_hash(image_path: Path) -> str:
    try:
        image = Image.open(image_path)
        phash = imagehash.average_hash(image)
        return str(phash)
    except Exception as e:
        logger.error(f"Error computing hash for {image_path}: {e}")
        return ""


def update_brand_hashes():
    logger.info("Starting hash generation for brand assets...")
    
    with open(BRANDS_JSON_PATH, 'r', encoding='utf-8') as f:
        brands_data = json.load(f)
    
    updated_count = 0
    
    for brand in brands_data['brands']:
        brand_id = brand['id']
        
        favicon_path = BRAND_FAVICONS_PATH / f"{brand_id}.png"
        if favicon_path.exists():
            favicon_hash = compute_image_hash(favicon_path)
            if favicon_hash:
                brand['favicon_hash'] = favicon_hash
                logger.info(f"Updated favicon hash for {brand['name']}")
                updated_count += 1
        
        logo_path = BRAND_LOGOS_PATH / f"{brand_id}.png"
        if logo_path.exists():
            logo_hash = compute_image_hash(logo_path)
            if logo_hash:
                brand['logo_hash'] = logo_hash
                logger.info(f"Updated logo hash for {brand['name']}")
                updated_count += 1
    
    with open(BRANDS_JSON_PATH, 'w', encoding='utf-8') as f:
        json.dump(brands_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Hash generation complete! Updated {updated_count} assets.")
    print(f"\n✓ Generated hashes for {updated_count} assets")
    print(f"Updated: {BRANDS_JSON_PATH}")


if __name__ == "__main__":
    update_brand_hashes()