"""
Dr. SSM Eye - DNS Analysis Module
"""

import dns.resolver
import time
from typing import List, Optional

from core.data_models import ModuleResult
from core.url_normalizer import extract_domain
from config.settings import (
    DNS_TIMEOUT, DNS_NO_A_RECORD_POINTS, DNS_NO_MX_RECORDS_POINTS,
    DNS_HAS_MX_RECORDS_POINTS, DNS_REPUTABLE_NS_POINTS,
    DNS_SKETCHY_NS_POINTS, DNS_SLOW_RESPONSE_POINTS, REPUTABLE_NAMESERVERS
)
from utils.logger import logger


def analyze_dns(url: str) -> ModuleResult:
    try:
        domain = extract_domain(url)
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        
        features = {
            "has_a_record": False,
            "mx_records": [],
            "nameservers": [],
            "response_time": 0.0
        }
        
        risk_contribution = 0
        
        start_time = time.time()
        
        try:
            a_records = resolver.resolve(domain, 'A')
            features["has_a_record"] = True
            features["ip_addresses"] = [str(r) for r in a_records]
        except:
            risk_contribution += DNS_NO_A_RECORD_POINTS
        
        try:
            mx_records = resolver.resolve(domain, 'MX')
            features["mx_records"] = [str(r.exchange) for r in mx_records]
            if features["mx_records"]:
                risk_contribution += DNS_HAS_MX_RECORDS_POINTS
            else:
                risk_contribution += DNS_NO_MX_RECORDS_POINTS
        except:
            risk_contribution += DNS_NO_MX_RECORDS_POINTS
        
        try:
            ns_records = resolver.resolve(domain, 'NS')
            features["nameservers"] = [str(r) for r in ns_records]
            
            reputable = any(
                ns.lower() in str(features["nameservers"]).lower()
                for ns in REPUTABLE_NAMESERVERS
            )
            
            if reputable:
                risk_contribution += DNS_REPUTABLE_NS_POINTS
            else:
                risk_contribution += DNS_SKETCHY_NS_POINTS
        except:
            pass
        
        response_time = time.time() - start_time
        features["response_time"] = round(response_time, 3)
        
        if response_time > 2.0:
            risk_contribution += DNS_SLOW_RESPONSE_POINTS
        
        confidence = 0.8 if features["has_a_record"] else 0.5
        
        return ModuleResult(
            module_name="dns_check",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"DNS check error for {url}: {e}")
        return ModuleResult(
            module_name="dns_check",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )