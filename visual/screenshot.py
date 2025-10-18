"""
Screenshot Capture Module
Captures website screenshots using Playwright
"""

import logging
import hashlib
from pathlib import Path
from typing import Dict, Tuple
from PIL import Image
from io import BytesIO

logger = logging.getLogger('dr_ssm_eye')


def capture_screenshot(url: str, timeout: int = 10000) -> Dict[str, str]:
    """
    Capture screenshot of URL
    
    Args:
        url: URL to capture
        timeout: Timeout in milliseconds
    
    Returns:
        Dictionary with thumbnail and full screenshot paths
    """
    try:
        from playwright.sync_api import sync_playwright
        
        url_hash = hashlib.md5(url.encode()).hexdigest()[:16]
        
        screenshots_dir = Path("storage/screenshots")
        thumbnails_dir = screenshots_dir / "thumbnails"
        full_dir = screenshots_dir / "full"
        
        thumbnails_dir.mkdir(parents=True, exist_ok=True)
        full_dir.mkdir(parents=True, exist_ok=True)
        
        thumbnail_path = thumbnails_dir / f"{url_hash}.png"
        full_path = full_dir / f"{url_hash}.png"
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': 800, 'height': 600})
            
            page.goto(url, wait_until='domcontentloaded', timeout=timeout)
            
            screenshot_bytes = page.screenshot(full_page=False)
            
            browser.close()
        
        with open(full_path, 'wb') as f:
            f.write(screenshot_bytes)
        
        img = Image.open(BytesIO(screenshot_bytes))
        img.thumbnail((100, 75))
        img.save(thumbnail_path, 'PNG')
        
        logger.info(f"Screenshot captured for {url}")
        
        return {
            'thumbnail': f"thumbnails/{url_hash}.png",
            'full': f"full/{url_hash}.png"
        }
    
    except Exception as e:
        logger.error(f"Screenshot capture error for {url}: {e}")
        return {
            'thumbnail': '',
            'full': ''
        }