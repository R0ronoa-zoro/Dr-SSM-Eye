"""
WHOIS domain information lookup using whoisfreaks.com
"""

import logging
from datetime import datetime
from typing import Optional
import http.client
import json

from core.data_models import ModuleResult
from core.url_normalizer import extract_domain

logger = logging.getLogger('dr_ssm_eye')

WHOISFREAKS_API_KEY = "813fa47a434f46689afd391e67cb7acb"

def check_whois(url: str) -> ModuleResult:
    try:
        domain = extract_domain(url)
        
        conn = http.client.HTTPSConnection("api.whoisfreaks.com")
        
        conn.request(
            "GET", 
            f"/v1.0/whois?apiKey={WHOISFREAKS_API_KEY}&whois=live&domainName={domain}",
            headers={}
        )
        
        res = conn.getresponse()
        data = res.read()
        
        if res.status == 200:
            whois_data = json.loads(data.decode("utf-8"))
            
            create_date_str = whois_data.get('create_date')
            expire_date_str = whois_data.get('expires_date')
            
            domain_age = None
            if create_date_str:
                try:
                    create_date = datetime.strptime(create_date_str, '%Y-%m-%d')
                    domain_age = (datetime.now() - create_date).days
                except:
                    try:
                        create_date = datetime.strptime(create_date_str.split('T')[0], '%Y-%m-%d')
                        domain_age = (datetime.now() - create_date).days
                    except:
                        logger.warning(f"Could not parse date: {create_date_str}")
            
            registrar_name = whois_data.get('registrar_name', 'Unknown')
            
            return ModuleResult(
                module_name="whois",
                features={
                    "domain_age_days": domain_age,
                    "registrar": registrar_name,
                    "registration_date": create_date_str,
                    "expiry_date": expire_date_str,
                    "whois_privacy": whois_data.get('privacy_protected', False)
                },
                risk_contribution=calculate_whois_risk(domain_age),
                confidence=0.9
            )
        else:
            logger.warning(f"WhoisFreaks returned status {res.status}")
            return ModuleResult(
                module_name="whois",
                features={"error": f"HTTP {res.status}", "domain_age_days": None},
                risk_contribution=0,
                confidence=0.0
            )
    
    except Exception as e:
        logger.error(f"WHOIS check error for {domain}: {e}")
        return ModuleResult(
            module_name="whois",
            features={"error": str(e), "domain_age_days": None},
            risk_contribution=0,
            confidence=0.0
        )

def calculate_whois_risk(domain_age_days):
    if domain_age_days is None:
        return 0
    elif domain_age_days < 7:
        return 30
    elif domain_age_days < 30:
        return 20
    elif domain_age_days < 365:
        return 10
    elif domain_age_days > 1095:
        return -30
    else:
        return 0
