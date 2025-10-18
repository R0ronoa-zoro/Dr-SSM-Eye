"""
Content Analysis Module
Analyzes page content for suspicious indicators
"""

import logging
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any
import re

from core.data_models import ModuleResult

logger = logging.getLogger('dr_ssm_eye')


def analyze_content(url: str, timeout: int = 10) -> ModuleResult:
    """
    Analyze page content for suspicious indicators
    
    Args:
        url: URL to analyze
        timeout: Request timeout in seconds
    
    Returns:
        ModuleResult with content analysis
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        
        if response.status_code != 200:
            return ModuleResult(
                module_name="content",
                features={
                    "error": f"HTTP {response.status_code}",
                    "has_password_field": False,
                    "suspicious_keywords": [],
                    "page_title": None
                },
                risk_contribution=0,
                confidence=0.0
            )
        
        html_content = response.text
        
        if not html_content or html_content.strip() == "":
            return ModuleResult(
                module_name="content",
                features={
                    "error": "Empty response",
                    "has_password_field": False,
                    "suspicious_keywords": [],
                    "page_title": None
                },
                risk_contribution=0,
                confidence=0.0
            )
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        page_title = soup.title.string if soup.title else None
        
        password_inputs = soup.find_all('input', {'type': 'password'})
        has_password_field = len(password_inputs) > 0
        
        suspicious_words = [
            'verify', 'urgent', 'suspended', 'limited time', 'expire',
            'update payment', 'confirm identity', 'account locked',
            'unusual activity', 'click here', 'act now'
        ]
        
        text_content = soup.get_text().lower() if soup.get_text() else ""
        
        found_keywords = []
        for word in suspicious_words:
            if word in text_content:
                found_keywords.append(word)
        
        meta_tags = soup.find_all('meta')
        has_meta = len(meta_tags) > 0
        
        external_scripts = soup.find_all('script', src=True)
        external_count = len([s for s in external_scripts if s.get('src', '').startswith('http')])
        
        risk = 0
        
        if has_password_field:
            risk += 20
        
        risk += len(found_keywords) * 10
        
        if not has_meta:
            risk += 5
        
        if external_count > 50:
            risk += 15
        
        if has_meta:
            risk -= 5
        
        if external_count < 10:
            risk -= 5
        
        return ModuleResult(
            module_name="content",
            features={
                "has_password_field": has_password_field,
                "page_title": page_title,
                "suspicious_keywords": found_keywords,
                "has_meta_tags": has_meta,
                "external_resources": external_count
            },
            risk_contribution=risk,
            confidence=0.7
        )
    
    except requests.Timeout:
        logger.warning(f"Content check timeout for {url}")
        return ModuleResult(
            module_name="content",
            features={
                "error": "timeout",
                "has_password_field": False,
                "suspicious_keywords": [],
                "page_title": None
            },
            risk_contribution=0,
            confidence=0.0
        )
    
    except requests.RequestException as e:
        logger.warning(f"Content check request error for {url}: {e}")
        return ModuleResult(
            module_name="content",
            features={
                "error": str(e),
                "has_password_field": False,
                "suspicious_keywords": [],
                "page_title": None
            },
            risk_contribution=0,
            confidence=0.0
        )
    
    except Exception as e:
        logger.error(f"Content check error for {url}: {e}")
        return ModuleResult(
            module_name="content",
            features={
                "error": str(e),
                "has_password_field": False,
                "suspicious_keywords": [],
                "page_title": None
            },
            risk_contribution=0,
            confidence=0.0
        )