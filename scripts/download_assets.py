"""
Dr. SSM Eye - Download Brand Assets
Script to automatically download favicons and capture screenshots
"""

import requests
from pathlib import Path
from PIL import Image
import io

from playwright.sync_api import sync_playwright
from config.settings import (
    BRANDS_JSON_PATH, BRAND_FAVICONS_PATH,
    BRAND_SCREENSHOTS_PATH
)
from utils.logger import logger
from utils.helpers import load_json_file


def download_favicon(domain: str, save_path: Path) -> bool:
    try:
        favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=128"
        
        response = requests.get(favicon_url, timeout=10)
        if response.status_code == 200:
            image = Image.open(io.BytesIO(response.content))
            image.save(save_path, 'PNG')
            logger.info(f"Downloaded favicon for {domain}")
            return True
    except Exception as e:
        logger.error(f"Failed to download favicon for {domain}: {e}")
    
    return False


def capture_screenshot(url: str, save_path: Path) -> bool:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': 800, 'height': 600})
            
            page.goto(f"https://{url}", timeout=15000, wait_until='networkidle')
            
            screenshot_bytes = page.screenshot()
            
            image = Image.open(io.BytesIO(screenshot_bytes))
            image.save(save_path, 'PNG')
            
            browser.close()
            
            logger.info(f"Captured screenshot for {url}")
            return True
            
    except Exception as e:
        logger.error(f"Failed to capture screenshot for {url}: {e}")
    
    return False


def download_all_assets():
    logger.info("Starting automated asset download...")
    
    brands_data = load_json_file(str(BRANDS_JSON_PATH))
    
    if not brands_data or 'brands' not in brands_data:
        logger.error("Brands database not found")
        return
    
    favicon_count = 0
    screenshot_count = 0
    
    for brand in brands_data['brands']:
        brand_id = brand['id']
        brand_name = brand['name']
        primary_domain = brand['domains'][0] if brand['domains'] else None
        
        if not primary_domain:
            continue
        
        print(f"\nProcessing: {brand_name}")
        
        favicon_path = BRAND_FAVICONS_PATH / f"{brand_id}.png"
        if not favicon_path.exists():
            if download_favicon(primary_domain, favicon_path):
                favicon_count += 1
                print(f"  ✓ Downloaded favicon")
            else:
                print(f"  ✗ Failed to download favicon")
        else:
            print(f"  ⊘ Favicon already exists")
        
        screenshot_path = BRAND_SCREENSHOTS_PATH / f"{brand_id}.png"
        if not screenshot_path.exists():
            if capture_screenshot(primary_domain, screenshot_path):
                screenshot_count += 1
                print(f"  ✓ Captured screenshot")
            else:
                print(f"  ✗ Failed to capture screenshot")
        else:
            print(f"  ⊘ Screenshot already exists")
    
    print(f"\n{'='*60}")
    print(f"Asset download complete!")
    print(f"Favicons: {favicon_count} downloaded")
    print(f"Screenshots: {screenshot_count} captured")
    print(f"{'='*60}")


if __name__ == "__main__":
    download_all_assets()