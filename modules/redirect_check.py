"""
Redirect Chain Tracking Module
Tracks redirect chains and detects suspicious patterns
"""

import logging
import requests
from typing import List, Dict, Any
from datetime import datetime

from core.data_models import ModuleResult

logger = logging.getLogger('dr_ssm_eye')


def track_redirects(url: str, max_hops: int = 5, timeout: int = 10) -> ModuleResult:
    """
    Follow redirect chain and detect suspicious patterns
    
    Args:
        url: Starting URL
        max_hops: Maximum redirects to follow
        timeout: Request timeout
    
    Returns:
        ModuleResult with redirect chain information
    """
    try:
        chain = []
        current_url = url
        hop_number = 0
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        session = requests.Session()
        session.max_redirects = 0
        
        while hop_number < max_hops:
            try:
                response = session.get(
                    current_url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
                
                chain.append({
                    'hop_number': hop_number,
                    'url': current_url,
                    'status_code': response.status_code,
                    'timestamp': datetime.now().isoformat()
                })
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    
                    if not location:
                        break
                    
                    if not location.startswith('http'):
                        from urllib.parse import urljoin
                        location = urljoin(current_url, location)
                    
                    current_url = location
                    hop_number += 1
                else:
                    break
            
            except requests.Timeout:
                logger.warning(f"Redirect tracking timeout at hop {hop_number}")
                break
            
            except requests.RequestException as e:
                logger.warning(f"Redirect tracking error at hop {hop_number}: {e}")
                break
        
        hop_count = len(chain) - 1 if len(chain) > 0 else 0
        final_url = chain[-1]['url'] if chain else url
        
        url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'shorturl.at', 'tiny.cc', 'is.gd', 'buff.ly', 'adf.ly'
        ]
        
        uses_shortener = any(
            shortener in hop.get('url', '') 
            for hop in chain 
            for shortener in url_shorteners
        )
        
        risk = 0
        
        if hop_count == 0:
            risk = 0
        elif hop_count <= 2:
            risk = 5
        elif hop_count <= 4:
            risk = 15
        else:
            risk = 25
        
        if uses_shortener:
            risk += 15
        
        if final_url != url:
            from urllib.parse import urlparse
            initial_domain = urlparse(url).netloc
            final_domain = urlparse(final_url).netloc
            
            if initial_domain != final_domain:
                risk += 10
        
        return ModuleResult(
            module_name="redirect",
            features={
                "hop_count": hop_count,
                "chain": chain,
                "final_url": final_url,
                "uses_shortener": uses_shortener
            },
            risk_contribution=risk,
            confidence=0.8
        )
    
    except Exception as e:
        logger.error(f"Redirect tracking critical error for {url}: {e}")
        return ModuleResult(
            module_name="redirect",
            features={
                "error": str(e),
                "hop_count": 0,
                "chain": [],
                "final_url": url,
                "uses_shortener": False
            },
            risk_contribution=0,
            confidence=0.0
        )