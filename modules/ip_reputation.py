"""
IP Reputation Module
Checks IP reputation against malicious IP database
"""

import logging
import socket
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import subprocess
import re

from core.data_models import ModuleResult
from storage.database import DatabaseManager

logger = logging.getLogger('dr_ssm_eye')


class IPReputationChecker:
    """Check IP reputation"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.logger = logging.getLogger('dr_ssm_eye')
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation in database
        
        Args:
            ip: IP address to check
        
        Returns:
            Dictionary with reputation info
        """
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT ip_address, asn, asn_name, country, 
                       last_seen, threat_type, confidence, source
                FROM malicious_ips
                WHERE ip_address = ?
            """, (ip,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                last_seen = datetime.strptime(result[4], '%Y-%m-%d')
                days_since = (datetime.now() - last_seen).days
                
                return {
                    'found': True,
                    'ip': result[0],
                    'asn': result[1],
                    'asn_name': result[2],
                    'country': result[3],
                    'last_seen': result[4],
                    'days_since_last_seen': days_since,
                    'threat_type': result[5],
                    'confidence': result[6],
                    'source': result[7]
                }
            
            return {'found': False}
        
        except Exception as e:
            self.logger.error(f"Error checking IP reputation: {e}")
            return {'found': False, 'error': str(e)}
    
    def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """
        Get ASN information for IP
        
        Args:
            ip: IP address
        
        Returns:
            Dictionary with ASN info
        """
        try:
            result = subprocess.run(
                ['whois', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout
            
            asn = None
            asn_name = None
            country = None
            
            asn_match = re.search(r'(?:origin|OriginAS):\s*AS(\d+)', output, re.IGNORECASE)
            if asn_match:
                asn = int(asn_match.group(1))
            
            name_match = re.search(r'(?:OrgName|org-name):\s*(.+)', output, re.IGNORECASE)
            if name_match:
                asn_name = name_match.group(1).strip()
            
            country_match = re.search(r'(?:Country|country):\s*([A-Z]{2})', output, re.IGNORECASE)
            if country_match:
                country = country_match.group(1)
            
            return {
                'asn': asn,
                'asn_name': asn_name,
                'country': country
            }
        
        except Exception as e:
            self.logger.warning(f"ASN lookup failed for {ip}: {e}")
            return {
                'asn': None,
                'asn_name': None,
                'country': None
            }


def check_ip_reputation(domain: str) -> ModuleResult:
    """
    Check IP reputation for domain
    
    Args:
        domain: Domain name to resolve and check
    
    Returns:
        ModuleResult with IP reputation data
    """
    try:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return ModuleResult(
                module_name="ip_reputation",
                features={
                    "error": "DNS resolution failed",
                    "ip": None,
                    "reputation": "unknown"
                },
                risk_contribution=0,
                confidence=0.0
            )
        
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            octets = ip.split('.')
            if ip.startswith('172.') and 16 <= int(octets[1]) <= 31:
                return ModuleResult(
                    module_name="ip_reputation",
                    features={
                        "ip": ip,
                        "reputation": "private",
                        "is_private": True
                    },
                    risk_contribution=-50,
                    confidence=1.0
                )
            elif ip.startswith('192.168.') or ip.startswith('10.'):
                return ModuleResult(
                    module_name="ip_reputation",
                    features={
                        "ip": ip,
                        "reputation": "private",
                        "is_private": True
                    },
                    risk_contribution=-50,
                    confidence=1.0
                )
        
        checker = IPReputationChecker()
        
        ip_data = checker.check_ip(ip)
        
        if ip_data.get('found'):
            days_since = ip_data.get('days_since_last_seen', 999)
            
            if days_since < 7:
                risk = 50
            elif days_since < 30:
                risk = 30
            elif days_since < 90:
                risk = 15
            else:
                risk = 5
            
            return ModuleResult(
                module_name="ip_reputation",
                features={
                    "ip": ip,
                    "reputation": "malicious",
                    "asn": ip_data.get('asn'),
                    "asn_name": ip_data.get('asn_name'),
                    "country": ip_data.get('country'),
                    "days_since_last_seen": days_since,
                    "threat_type": ip_data.get('threat_type'),
                    "source": ip_data.get('source')
                },
                risk_contribution=risk,
                confidence=0.9
            )
        
        asn_info = checker.get_asn_info(ip)
        
        return ModuleResult(
            module_name="ip_reputation",
            features={
                "ip": ip,
                "reputation": "unknown",
                "asn": asn_info.get('asn'),
                "asn_name": asn_info.get('asn_name'),
                "country": asn_info.get('country')
            },
            risk_contribution=0,
            confidence=0.5
        )
    
    except Exception as e:
        logger.error(f"IP reputation check error for {domain}: {e}")
        return ModuleResult(
            module_name="ip_reputation",
            features={
                "error": str(e),
                "ip": None,
                "reputation": "unknown"
            },
            risk_contribution=0,
            confidence=0.0
        )