"""
Visual Analysis Package
"""

from .screenshot import capture_screenshot
from .favicon_match import extract_and_match_favicon
from .logo_detection import detect_logo
from .similarity import calculate_visual_similarity

__all__ = [
    'capture_screenshot',
    'extract_and_match_favicon',
    'detect_logo',
    'calculate_visual_similarity'
]