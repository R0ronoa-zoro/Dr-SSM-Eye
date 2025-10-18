"""
Reasoning Generation Module
Generates human-readable explanations for classification decisions
"""

import logging
from typing import List, Dict, Any, Tuple
from datetime import datetime

from core.data_models import Reason, ScanResult, ModuleResult

logger = logging.getLogger('dr_ssm_eye')


class ReasoningEngine:
    """Generate explainable reasoning for URL classifications"""
    
    def __init__(self):
        self.logger = logging.getLogger('dr_ssm_eye')
    
    def generate_reasoning(
        self,
        features: Dict[str, Any],
        module_results: List[ModuleResult],
        risk_score: int,
        classification: str,
        brand_detected: str = None
    ) -> List[Reason]:
        """
        Generate human-readable reasoning for classification
        
        Args:
            features: Aggregated feature dictionary
            module_results: List of all module results
            risk_score: Calculated risk score
            classification: Final classification
            brand_detected: Detected brand name (if any)
        
        Returns:
            List of Reason objects with human-readable descriptions
        """
        reasons = []
        
        # Threat Intelligence
        threat_result = self._find_module_result(module_results, "threat_intel")
        if threat_result and threat_result.features.get("threat_found"):
            sources = threat_result.features.get("sources", [])
            if sources:
                source_names = ", ".join(sources)
                reasons.append(Reason(
                    feature="threat_database",
                    value=source_names,
                    points=threat_result.risk_contribution,
                    impact="negative",
                    description=f"URL found in known threat databases: {source_names}"
                ))
        
        # Whitelist Status
        whitelist_result = self._find_module_result(module_results, "whitelist")
        if whitelist_result:
            tier = whitelist_result.features.get("tier")
            if tier == "top_10k":
                reasons.append(Reason(
                    feature="whitelist",
                    value=tier,
                    points=whitelist_result.risk_contribution,
                    impact="positive",
                    description="Domain is in top 10,000 most popular websites globally"
                ))
            elif tier == "top_100k":
                reasons.append(Reason(
                    feature="whitelist",
                    value=tier,
                    points=whitelist_result.risk_contribution,
                    impact="positive",
                    description="Domain is in top 100,000 most popular websites"
                ))
        
        # Brand Impersonation
        brand_result = self._find_module_result(module_results, "brand_check")
        if brand_result and brand_result.features.get("brand_detected"):
            brand_name = brand_result.features.get("brand_detected")
            is_official = brand_result.features.get("is_official_domain", False)
            
            if is_official:
                reasons.append(Reason(
                    feature="brand_official",
                    value=brand_name,
                    points=brand_result.risk_contribution,
                    impact="positive",
                    description=f"Official {brand_name} domain - legitimate website"
                ))
            else:
                impersonation_type = brand_result.features.get("impersonation_type", "unknown")
                if impersonation_type != "none":
                    reasons.append(Reason(
                        feature="brand_impersonation",
                        value=brand_name,
                        points=brand_result.risk_contribution,
                        impact="negative",
                        description=f"Potential {brand_name} impersonation detected"
                    ))
                    
                    # Add specific evidence
                    evidence = brand_result.features.get("evidence", {})
                    if evidence.get("favicon_match"):
                        reasons.append(Reason(
                            feature="favicon_match",
                            value=brand_name,
                            points=0,
                            impact="negative",
                            description=f"Website favicon matches {brand_name} branding"
                        ))
                    if evidence.get("logo_detected"):
                        reasons.append(Reason(
                            feature="logo_detected",
                            value=brand_name,
                            points=0,
                            impact="negative",
                            description=f"{brand_name} logo found on page"
                        ))
        
        # Typosquatting
        typo_result = self._find_module_result(module_results, "typosquat")
        if typo_result and typo_result.features.get("is_typosquat"):
            target_brand = typo_result.features.get("target_brand")
            similarity = typo_result.features.get("similarity", 0)
            technique = typo_result.features.get("technique", "unknown")
            
            if target_brand:
                reasons.append(Reason(
                    feature="typosquatting",
                    value=target_brand,
                    points=typo_result.risk_contribution,
                    impact="negative",
                    description=f"Domain is a typosquat of {target_brand} (similarity: {similarity:.0%})"
                ))
        
        # Domain Age
        whois_result = self._find_module_result(module_results, "whois")
        if whois_result:
            domain_age = whois_result.features.get("domain_age_days")
            if domain_age is not None:
                if domain_age < 7:
                    reasons.append(Reason(
                        feature="domain_age",
                        value=domain_age,
                        points=whois_result.risk_contribution,
                        impact="negative",
                        description=f"Domain registered only {domain_age} days ago - very new"
                    ))
                elif domain_age < 30:
                    reasons.append(Reason(
                        feature="domain_age",
                        value=domain_age,
                        points=whois_result.risk_contribution,
                        impact="negative",
                        description=f"Domain registered {domain_age} days ago - recently created"
                    ))
                elif domain_age > 1095:  # 3 years
                    years = domain_age // 365
                    reasons.append(Reason(
                        feature="domain_age",
                        value=domain_age,
                        points=whois_result.risk_contribution,
                        impact="positive",
                        description=f"Domain is {years} years old - well established"
                    ))
        
        # SSL Certificate
        ssl_result = self._find_module_result(module_results, "ssl")
        if ssl_result:
            has_https = ssl_result.features.get("has_https", False)
            self_signed = ssl_result.features.get("self_signed", False)
            
            if not has_https:
                reasons.append(Reason(
                    feature="no_https",
                    value=False,
                    points=ssl_result.risk_contribution,
                    impact="negative",
                    description="Website does not use HTTPS encryption"
                ))
            elif self_signed:
                reasons.append(Reason(
                    feature="self_signed_cert",
                    value=True,
                    points=ssl_result.risk_contribution,
                    impact="negative",
                    description="Website uses self-signed SSL certificate"
                ))
            else:
                issuer = ssl_result.features.get("issuer", "")
                if "DigiCert" in issuer or "Sectigo" in issuer or "GlobalSign" in issuer:
                    reasons.append(Reason(
                        feature="commercial_ssl",
                        value=issuer,
                        points=ssl_result.risk_contribution,
                        impact="positive",
                        description=f"Valid SSL certificate issued by {issuer}"
                    ))
        
        # IP Reputation
        ip_result = self._find_module_result(module_results, "ip_reputation")
        if ip_result:
            reputation = ip_result.features.get("reputation")
            if reputation == "malicious":
                days_since = ip_result.features.get("days_since_last_seen", 0)
                if days_since < 7:
                    reasons.append(Reason(
                        feature="malicious_ip",
                        value=reputation,
                        points=ip_result.risk_contribution,
                        impact="negative",
                        description="IP address recently reported for malicious activity"
                    ))
                else:
                    reasons.append(Reason(
                        feature="malicious_ip",
                        value=reputation,
                        points=ip_result.risk_contribution,
                        impact="negative",
                        description="IP address previously reported for malicious activity"
                    ))
            elif reputation == "private":
                reasons.append(Reason(
                    feature="private_ip",
                    value=reputation,
                    points=ip_result.risk_contribution,
                    impact="positive",
                    description="Private/local IP address"
                ))
        
        # DNS Analysis
        dns_result = self._find_module_result(module_results, "dns")
        if dns_result:
            has_a_record = dns_result.features.get("has_a_record", True)
            has_mx = dns_result.features.get("mx_records", [])
            
            if not has_a_record:
                reasons.append(Reason(
                    feature="no_dns",
                    value=False,
                    points=dns_result.risk_contribution,
                    impact="negative",
                    description="Domain does not resolve to any IP address"
                ))
            
            if has_mx and len(has_mx) > 0:
                reasons.append(Reason(
                    feature="has_email",
                    value=True,
                    points=dns_result.risk_contribution,
                    impact="positive",
                    description="Domain has configured email servers"
                ))
        
        # Redirects
        redirect_result = self._find_module_result(module_results, "redirect")
        if redirect_result:
            hop_count = redirect_result.features.get("hop_count", 0)
            if hop_count > 0:
                chain = redirect_result.features.get("chain", [])
                final_url = redirect_result.features.get("final_url", "")
                
                if hop_count >= 3:
                    reasons.append(Reason(
                        feature="multiple_redirects",
                        value=hop_count,
                        points=redirect_result.risk_contribution,
                        impact="negative",
                        description=f"URL redirects {hop_count} times before reaching destination"
                    ))
                
                # Check for URL shortener
                if any("bit.ly" in str(hop) or "tinyurl" in str(hop) or "shorturl" in str(hop) for hop in chain):
                    reasons.append(Reason(
                        feature="url_shortener",
                        value=True,
                        points=0,
                        impact="negative",
                        description="URL uses a URL shortening service"
                    ))
        
        # Content Analysis
        content_result = self._find_module_result(module_results, "content")
        if content_result:
            has_password = content_result.features.get("has_password_field", False)
            suspicious_keywords = content_result.features.get("suspicious_keywords", [])
            
            if has_password:
                reasons.append(Reason(
                    feature="password_field",
                    value=True,
                    points=content_result.risk_contribution,
                    impact="negative",
                    description="Page contains password input field - potential credential theft"
                ))
            
            if suspicious_keywords:
                keywords_str = ", ".join(suspicious_keywords[:3])  # Limit to first 3
                reasons.append(Reason(
                    feature="suspicious_keywords",
                    value=suspicious_keywords,
                    points=content_result.risk_contribution,
                    impact="negative",
                    description=f"Page contains suspicious keywords: {keywords_str}"
                ))
        
        # Sort by impact (negative first, then positive)
        negative_reasons = [r for r in reasons if r.impact == "negative"]
        positive_reasons = [r for r in reasons if r.impact == "positive"]
        
        # Sort by absolute point value
        negative_reasons.sort(key=lambda r: abs(r.points), reverse=True)
        positive_reasons.sort(key=lambda r: abs(r.points), reverse=True)
        
        return negative_reasons + positive_reasons
    
    def _find_module_result(self, module_results: List[ModuleResult], module_name: str) -> ModuleResult:
        """Find module result by name"""
        for result in module_results:
            if result.module_name == module_name:
                return result
        return None
    
    def format_reasoning_for_display(self, reasons: List[Reason], classification: str) -> str:
        """
        Format reasoning for UI display
        
        Args:
            reasons: List of Reason objects
            classification: Final classification
        
        Returns:
            Formatted HTML string
        """
        if not reasons:
            return "<p>No specific indicators found. Classification based on baseline analysis.</p>"
        
        # Separate by impact
        negative = [r for r in reasons if r.impact == "negative"]
        positive = [r for r in reasons if r.impact == "positive"]
        
        html = []
        
        if negative:
            html.append("<h4>⚠️ Risk Indicators:</h4>")
            html.append("<ul>")
            for reason in negative:
                html.append(f"<li>{reason.description}</li>")
            html.append("</ul>")
        
        if positive:
            html.append("<h4>✓ Trust Indicators:</h4>")
            html.append("<ul>")
            for reason in positive:
                html.append(f"<li>{reason.description}</li>")
            html.append("</ul>")
        
        return "\n".join(html)
    
    def format_reasoning_for_pdf(self, reasons: List[Reason], classification: str) -> str:
        """
        Format reasoning for PDF report
        
        Args:
            reasons: List of Reason objects
            classification: Final classification
        
        Returns:
            Formatted text string
        """
        if not reasons:
            return "No specific indicators found. Classification based on baseline analysis."
        
        # Separate by impact
        negative = [r for r in reasons if r.impact == "negative"]
        positive = [r for r in reasons if r.impact == "positive"]
        
        lines = []
        
        if negative:
            lines.append("RISK INDICATORS:")
            for i, reason in enumerate(negative, 1):
                lines.append(f"  {i}. {reason.description}")
            lines.append("")
        
        if positive:
            lines.append("TRUST INDICATORS:")
            for i, reason in enumerate(positive, 1):
                lines.append(f"  {i}. {reason.description}")
            lines.append("")
        
        return "\n".join(lines)
    
    def apply_context_rules(
        self,
        features: Dict[str, Any],
        risk_score: int,
        module_results: List[ModuleResult]
    ) -> Tuple[int, str]:
        """
        Apply context-aware adjustments to score
        
        Args:
            features: Feature dictionary
            risk_score: Current risk score
            module_results: List of module results
        
        Returns:
            Tuple of (adjusted_score, context_note)
        """
        context_note = ""
        adjusted_score = risk_score if risk_score is not None else 0
        
        brand_result = self._find_module_result(module_results, "brand_check")
        whois_result = self._find_module_result(module_results, "whois")
        
        if brand_result and whois_result:
            logo_detected = brand_result.features.get("evidence", {}).get("logo_detected", False)
            favicon_match = brand_result.features.get("evidence", {}).get("favicon_match", False)
            domain_age = whois_result.features.get("domain_age_days", 0)
            
            if domain_age is None:
                domain_age = 0
            
            if logo_detected and not favicon_match and domain_age > 365:
                adjusted_score -= 60
                context_note = "Likely legitimate use of brand for payment integration"
        
        whitelist_result = self._find_module_result(module_results, "whitelist")
        if whitelist_result and whitelist_result.features.get("tier") == "top_10k":
            if adjusted_score > 20:
                adjusted_score = 20
                context_note = "Well-known domain, capping suspicious score"
        
        if whois_result:
            domain_age = whois_result.features.get("domain_age_days", 999)
            if domain_age is None:
                domain_age = 999
                
            dns_result = self._find_module_result(module_results, "dns")
            ssl_result = self._find_module_result(module_results, "ssl")
            threat_result = self._find_module_result(module_results, "threat_intel")
            
            has_mx = dns_result and len(dns_result.features.get("mx_records", [])) > 0
            has_ssl = ssl_result and ssl_result.features.get("has_https", False)
            no_threats = threat_result and not threat_result.features.get("threat_found", False)
            
            if domain_age < 30 and has_mx and has_ssl and no_threats:
                adjusted_score = int(adjusted_score * 0.5)
                context_note = "New domain but shows legitimate business indicators"
        
        return adjusted_score, context_note

def generate_recommendation(classification: str, confidence: float, risk_score: int) -> str:
    """
    Generate actionable recommendation based on classification
    
    Args:
        classification: CLEAN, SUSPICIOUS, MALICIOUS, ANALYST_REQUIRED
        confidence: Confidence percentage (0-100)
        risk_score: Risk score (-100 to +200)
    
    Returns:
        Recommendation string
    """
    if classification == "CLEAN":
        if confidence > 90:
            return "✓ Safe to proceed - URL appears legitimate"
        else:
            return "✓ Likely safe, but verify sender if received via email"
    
    elif classification == "SUSPICIOUS":
        return "⚠️ Exercise caution - Do not enter sensitive information without verification"
    
    elif classification == "MALICIOUS":
        return "❌ DO NOT VISIT - High confidence phishing/malicious site"
    
    elif classification == "ANALYST_REQUIRED":
        return "⚠️ Manual review recommended - Mixed signals detected"
    
    return "Unknown classification"
