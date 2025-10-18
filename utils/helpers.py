"""
Dr. SSM Eye - Helper Functions
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
import time
from functools import wraps


def generate_url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def get_current_timestamp() -> datetime:
    return datetime.now()


def format_timestamp(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def parse_timestamp(timestamp_str: str) -> datetime:
    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')


def days_between(date1: datetime, date2: datetime) -> int:
    return abs((date2 - date1).days)


def is_expired(timestamp: datetime, ttl_hours: int) -> bool:
    expiry = timestamp + timedelta(hours=ttl_hours)
    return datetime.now() > expiry


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    try:
        return numerator / denominator if denominator != 0 else default
    except:
        return default


def clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(value, max_value))


def load_json_file(file_path: str) -> Dict[str, Any]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return {}


def save_json_file(file_path: str, data: Dict[str, Any]) -> bool:
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        return False


def timer(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = (time.time() - start) * 1000
        return result, elapsed
    return wrapper


def chunk_list(lst: list, chunk_size: int) -> list:
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def bytes_to_mb(bytes_value: int) -> float:
    return bytes_value / (1024 * 1024)


def mb_to_bytes(mb_value: float) -> int:
    return int(mb_value * 1024 * 1024)