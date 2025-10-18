"""
Dr. SSM Eye - URL Normalization
"""

from urllib.parse import urlparse, urlunparse
from typing import Optional
import re
import idna


def normalize_url(url: str) -> str:
    if not url:
        return ""
    
    url = url.strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    if netloc.startswith('www.'):
        netloc = netloc[4:]
    
    try:
        netloc = idna.encode(netloc).decode('ascii')
    except:
        pass
    
    path = parsed.path.rstrip('/')
    if not path:
        path = ''
    
    normalized = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ''
    ))
    
    return normalized


def extract_domain(url: str) -> str:
    parsed = urlparse(url if url.startswith('http') else 'https://' + url)
    domain = parsed.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def extract_base_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def extract_tld(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-1]
    return ""


def count_subdomains(domain: str) -> int:
    parts = domain.split('.')
    return max(0, len(parts) - 2)


def has_ip_address(url: str) -> bool:
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    return bool(re.search(ip_pattern, url))


def calculate_url_entropy(url: str) -> float:
    import math
    from collections import Counter
    
    if not url:
        return 0.0
    
    counts = Counter(url)
    length = len(url)
    
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def get_digit_letter_ratio(text: str) -> float:
    if not text:
        return 0.0
    
    digits = sum(c.isdigit() for c in text)
    letters = sum(c.isalpha() for c in text)
    
    if letters == 0:
        return float(digits)
    
    return digits / letters


def contains_at_symbol(url: str) -> bool:
    return '@' in url


def count_hyphens(domain: str) -> int:
    return domain.count('-')


def extract_port(url: str) -> Optional[int]:
    parsed = urlparse(url if url.startswith('http') else 'https://' + url)
    return parsed.port


def is_standard_port(port: Optional[int], scheme: str) -> bool:
    if port is None:
        return True
    
    standard_ports = {'http': 80, 'https': 443}
    return port == standard_ports.get(scheme.lower())