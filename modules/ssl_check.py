"""
Dr. SSM Eye - SSL Certificate Check Module
"""

import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

from core.data_models import ModuleResult
from core.url_normalizer import extract_domain
from config.settings import (
    SSL_NO_HTTPS_POINTS, SSL_SELF_SIGNED_POINTS, SSL_VERY_NEW_POINTS,
    SSL_NEW_POINTS, SSL_OLD_POINTS, SSL_COMMERCIAL_CA_POINTS,
    HTTP_REQUEST_TIMEOUT
)
from utils.logger import logger
from utils.helpers import days_between


def check_ssl_certificate(url: str) -> ModuleResult:
    try:
        domain = extract_domain(url)
        
        features = {
            "has_https": False,
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "self_signed": False,
            "certificate_age_days": None
        }
        
        risk_contribution = 0
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=HTTP_REQUEST_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    
                    features["has_https"] = True
                    
                    issuer = cert.get_issuer()
                    issuer_str = ", ".join([
                        f"{name.decode()}={value.decode()}"
                        for name, value in issuer.get_components()
                    ])
                    features["issuer"] = issuer_str
                    
                    not_before = datetime.strptime(
                        cert.get_notBefore().decode('ascii'),
                        '%Y%m%d%H%M%SZ'
                    )
                    not_after = datetime.strptime(
                        cert.get_notAfter().decode('ascii'),
                        '%Y%m%d%H%M%SZ'
                    )
                    
                    features["valid_from"] = not_before.isoformat()
                    features["valid_to"] = not_after.isoformat()
                    
                    cert_age = days_between(not_before, datetime.now())
                    features["certificate_age_days"] = cert_age
                    
                    subject = cert.get_subject()
                    subject_str = ", ".join([
                        f"{name.decode()}={value.decode()}"
                        for name, value in subject.get_components()
                    ])
                    
                    if issuer_str == subject_str:
                        features["self_signed"] = True
                        risk_contribution += SSL_SELF_SIGNED_POINTS
                    
                    if cert_age < 7:
                        risk_contribution += SSL_VERY_NEW_POINTS
                    elif cert_age < 30:
                        risk_contribution += SSL_NEW_POINTS
                    elif cert_age > 365:
                        risk_contribution += SSL_OLD_POINTS
                    
                    commercial_cas = ["DigiCert", "Sectigo", "GlobalSign", "Entrust", "GoDaddy"]
                    if any(ca in issuer_str for ca in commercial_cas):
                        risk_contribution += SSL_COMMERCIAL_CA_POINTS
                    
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {domain}: {e}")
            risk_contribution += SSL_NO_HTTPS_POINTS
        except socket.timeout:
            logger.warning(f"SSL check timeout for {domain}")
            risk_contribution += SSL_NO_HTTPS_POINTS
        except Exception as e:
            logger.warning(f"SSL check failed for {domain}: {e}")
            risk_contribution += SSL_NO_HTTPS_POINTS
        
        confidence = 0.85 if features["has_https"] else 0.6
        
        return ModuleResult(
            module_name="ssl_check",
            features=features,
            risk_contribution=risk_contribution,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"SSL check error for {url}: {e}")
        return ModuleResult(
            module_name="ssl_check",
            features={"error": str(e)},
            risk_contribution=0,
            confidence=0.0,
            error=str(e)
        )