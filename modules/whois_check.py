"""
Dr. SSM Eye - WHOIS Lookup Module
"""

import whois
from datetime import datetime

from core.data_models import ModuleResult
from core.url_normalizer import extract_domain
from config.settings import (
    WHOIS_TIMEOUT, DOMAIN_AGE_VERY_NEW_POINTS, DOMAIN_AGE_NEW_POINTS,
    DOMAIN_AGE_RECENT_POINTS, DOMAIN_AGE_NEUTRAL_POINTS,
    DOMAIN_AGE_ESTABLISHED_POINTS, WHOIS_PRIVACY_POINTS,
    WHOIS_SKETCHY_REGISTRAR_POINTS, SKETCHY_REGISTRARS
)
from utils.logger import logger
from utils.helpers import days_between


def check_whois(url: str) -> ModuleResult:
    try:
        domain = extract_domain(url)
        
        try:
            whois_data = whois.whois(domain)
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return ModuleResult(
                module_name="whois_check",
                features={"error": "WHOIS lookup failed"},
                risk_contribution=0,
                confidence=0.0,
                error=str(e)
            )
        
        features = {
            "domain_age_days": None,
            "registrar": None,
            "registration_date": None,
            "expiry_date": None,
            "whois_privacy": False
        }
        
        risk_contribution = 0
        
        creation_date = whois_data.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            from datetime import timezone
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            domain_age = days_between(creation_date, now)
            features["domain_age_days"] = domain_age
            features["registration_date"] = creation_date.isoformat()
            
            if domain_age < 7:
                risk_contribution += DOMAIN_AGE_VERY_NEW_POINTS
            elif domain_age < 30:
                risk_contribution += DOMAIN_AGE_NEW_POINTS
            elif domain_age < 365:
                risk_contribution += DOMAIN_AGE_RECENT_POINTS
            elif domain_age < 1095:
                risk_contribution += DOMAIN_AGE_NEUTRAL_POINTS
            else:
                risk_contribution += DOMAIN_AGE_ESTABLISHED_POINTS
        
        expiry_date = whois_data.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        
        if expiry_date:
            features["expiry_date"] = expiry_date.isoformat()
        
        registrar = whois_data.registrar
        if registrar:
            features["registrar"] = registrar
            
            if any(sketchy.lower() in registrar.lower() for sketchy in SKETCHY_REGISTRARS):
                risk_contribution += WHOIS_SKETCHY_REGISTRAR_POINTS
        
        whois_server = whois_data.whois_server
        if whois_server and "privacy" in str(whois_server).lower():
            features["whois_privacy"] = True
            risk_contribution += WHOIS_PRIVACY_POINTS
        
        confidence = 0.8 if features["domain_age_days"] is not None else 0.3
        
        return ModuleResult(
            module_name="whois_check",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"WHOIS check error for {url}: {e}")
        return ModuleResult(
            module_name="whois_check",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )