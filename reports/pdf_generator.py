"""
PDF Report Generator
Generates PDF reports for scan results
"""

import logging
from io import BytesIO
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from intelligence.reasoning import ReasoningEngine

logger = logging.getLogger('dr_ssm_eye')


class PDFGenerator:
    """Generate PDF reports"""
    
    def __init__(self):
        self.reasoning_engine = ReasoningEngine()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=12
        ))
    
    def generate_per_url_report(self, scan_data: Dict[str, Any]) -> bytes:
        """
        Generate detailed PDF report for single URL
        
        Args:
            scan_data: Scan result dictionary
        
        Returns:
            PDF bytes
        """
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            
            story.append(Paragraph("Dr. SSM Eye", self.styles['CustomTitle']))
            story.append(Paragraph("URL Analysis Report", self.styles['CustomHeading']))
            story.append(Spacer(1, 0.3*inch))
            
            classification = scan_data.get('classification', 'UNKNOWN')
            confidence = scan_data.get('confidence', 0) * 100
            risk_score = scan_data.get('risk_score', 0)
            url = scan_data.get('url', 'N/A')
            timestamp = scan_data.get('last_scanned', datetime.now())
            
            story.append(Paragraph("<b>Executive Summary</b>", self.styles['CustomHeading']))
            story.append(Paragraph(f"<b>URL:</b> {url}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Classification:</b> {classification}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Confidence:</b> {confidence:.1f}%", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Risk Score:</b> {risk_score}/200", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Scanned:</b> {timestamp}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.3*inch))
            
            features = scan_data.get('features', {})
            
            story.append(Paragraph("<b>URL Information</b>", self.styles['CustomHeading']))
            story.append(Paragraph(f"<b>Source URL:</b> {url}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Normalized URL:</b> {scan_data.get('normalized_url', url)}", self.styles['CustomBody']))
            
            redirect_chain = features.get('redirect_chain', [])
            if redirect_chain:
                dest_url = redirect_chain[-1].get('url', url)
                story.append(Paragraph(f"<b>Destination URL:</b> {dest_url}", self.styles['CustomBody']))
                story.append(Paragraph(f"<b>Redirect Hops:</b> {len(redirect_chain)}", self.styles['CustomBody']))
            
            story.append(Spacer(1, 0.2*inch))
            
            story.append(Paragraph("<b>Brand Detection</b>", self.styles['CustomHeading']))
            brand_detected = features.get('brand_check_brand_detected', 'None')
            is_official = features.get('brand_check_is_official_domain', False)
            story.append(Paragraph(f"<b>Brand Detected:</b> {brand_detected}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Official Domain:</b> {'Yes' if is_official else 'No'}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.2*inch))
            
            story.append(Paragraph("<b>Network Information</b>", self.styles['CustomHeading']))
            ip_address = features.get('ip_reputation_ip', 'N/A')
            asn = features.get('ip_reputation_asn', 'N/A')
            asn_name = features.get('ip_reputation_asn_name', 'N/A')
            country = features.get('ip_reputation_country', 'N/A')
            story.append(Paragraph(f"<b>IP Address:</b> {ip_address}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>ASN:</b> {asn} ({asn_name})", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Country:</b> {country}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.2*inch))
            
            story.append(Paragraph("<b>Domain Information</b>", self.styles['CustomHeading']))
            domain_age = features.get('whois_domain_age_days', 'Unknown')
            registrar = features.get('whois_registrar', 'N/A')
            reg_date = features.get('whois_registration_date', 'N/A')
            exp_date = features.get('whois_expiry_date', 'N/A')
            story.append(Paragraph(f"<b>Domain Age:</b> {domain_age} days" if domain_age != 'Unknown' else f"<b>Domain Age:</b> Unknown", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Registrar:</b> {registrar}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Registration Date:</b> {reg_date}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Expiry Date:</b> {exp_date}", self.styles['CustomBody']))
            
            mx_records = features.get('dns_check_mx_records', [])
            if mx_records:
                story.append(Paragraph(f"<b>MX Records:</b> {', '.join(mx_records)}", self.styles['CustomBody']))
            else:
                story.append(Paragraph(f"<b>MX Records:</b> None", self.styles['CustomBody']))
            
            nameservers = features.get('dns_check_nameservers', [])
            if nameservers:
                story.append(Paragraph(f"<b>Nameservers:</b> {', '.join(nameservers[:3])}", self.styles['CustomBody']))
            
            story.append(Spacer(1, 0.2*inch))
            
            story.append(Paragraph("<b>SSL Certificate</b>", self.styles['CustomHeading']))
            has_https = features.get('ssl_has_https', False)
            ssl_issuer = features.get('ssl_issuer', 'N/A')
            ssl_valid_from = features.get('ssl_valid_from', 'N/A')
            ssl_valid_to = features.get('ssl_valid_to', 'N/A')
            story.append(Paragraph(f"<b>Has HTTPS:</b> {'Yes' if has_https else 'No'}", self.styles['CustomBody']))
            if has_https:
                story.append(Paragraph(f"<b>Issuer:</b> {ssl_issuer}", self.styles['CustomBody']))
                story.append(Paragraph(f"<b>Valid From:</b> {ssl_valid_from}", self.styles['CustomBody']))
                story.append(Paragraph(f"<b>Valid To:</b> {ssl_valid_to}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.2*inch))
            
            story.append(Paragraph("<b>Content Analysis</b>", self.styles['CustomHeading']))
            page_title = features.get('content_page_title', 'N/A')
            has_password = features.get('content_has_password_field', False)
            suspicious_kw = features.get('content_suspicious_keywords', [])
            story.append(Paragraph(f"<b>Page Title:</b> {page_title}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Has Password Field:</b> {'Yes' if has_password else 'No'}", self.styles['CustomBody']))
            if suspicious_kw:
                story.append(Paragraph(f"<b>Suspicious Keywords:</b> {', '.join(suspicious_kw)}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.2*inch))
            
            story.append(Paragraph("<b>Threat Intelligence</b>", self.styles['CustomHeading']))
            in_threat_db = features.get('threat_intel_threat_found', False)
            threat_sources = features.get('threat_intel_sources', [])
            in_whitelist = features.get('whitelist_check_in_whitelist', False)
            tranco_rank = features.get('whitelist_check_tranco_rank')
            story.append(Paragraph(f"<b>In Threat Database:</b> {'Yes' if in_threat_db else 'No'}", self.styles['CustomBody']))
            if threat_sources:
                story.append(Paragraph(f"<b>Threat Sources:</b> {', '.join(threat_sources)}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>In Whitelist:</b> {'Yes' if in_whitelist else 'No'}", self.styles['CustomBody']))
            if tranco_rank:
                story.append(Paragraph(f"<b>Tranco Rank:</b> {tranco_rank}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.3*inch))
            
            story.append(Paragraph("<b>Analysis</b>", self.styles['CustomHeading']))
            
            reasoning = scan_data.get('reasoning', [])
            if reasoning:
                reasoning_text = self.reasoning_engine.format_reasoning_for_pdf(
                    [type('obj', (object,), r) for r in reasoning],
                    classification
                )
                for line in reasoning_text.split('\n'):
                    if line.strip():
                        story.append(Paragraph(line, self.styles['CustomBody']))
            else:
                story.append(Paragraph("No specific indicators found.", self.styles['CustomBody']))
            
            story.append(Spacer(1, 0.3*inch))
            
            recommendation = self._get_recommendation(classification, confidence)
            story.append(Paragraph(f"<b>Recommendation:</b> {recommendation}", self.styles['CustomBody']))
            
            story.append(Spacer(1, 0.5*inch))
            story.append(Paragraph("Generated by Dr. SSM Eye", self.styles['CustomBody']))
            story.append(Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['CustomBody']))
            
            doc.build(story)
            
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            logger.info(f"Generated PDF report for {url}")
            return pdf_bytes
        
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            raise
    
    def _get_recommendation(self, classification: str, confidence: float) -> str:
        """Get recommendation based on classification"""
        if classification == "CLEAN":
            if confidence > 90:
                return "Safe to proceed - URL appears legitimate"
            else:
                return "Likely safe, but verify sender if received via email"
        elif classification == "SUSPICIOUS":
            return "Exercise caution - Do not enter sensitive information without verification"
        elif classification == "MALICIOUS":
            return "DO NOT VISIT - High confidence phishing/malicious site"
        elif classification == "ANALYST_REQUIRED":
            return "Manual review recommended - Mixed signals detected"
        return "Unknown classification"
    
    def generate_batch_summary_report(self, scan_results: List[Dict[str, Any]]) -> bytes:
        """
        Generate batch summary report
        
        Args:
            scan_results: List of scan result dictionaries
        
        Returns:
            PDF bytes
        """
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            
            story.append(Paragraph("Dr. SSM Eye", self.styles['CustomTitle']))
            story.append(Paragraph("Batch Scan Summary", self.styles['CustomHeading']))
            story.append(Spacer(1, 0.3*inch))
            
            total = len(scan_results)
            clean = sum(1 for r in scan_results if r.get('classification') == 'CLEAN')
            suspicious = sum(1 for r in scan_results if r.get('classification') == 'SUSPICIOUS')
            malicious = sum(1 for r in scan_results if r.get('classification') == 'MALICIOUS')
            analyst = sum(1 for r in scan_results if r.get('classification') == 'ANALYST_REQUIRED')
            
            story.append(Paragraph(f"<b>Total URLs Scanned:</b> {total}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Clean:</b> {clean}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Suspicious:</b> {suspicious}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Malicious:</b> {malicious}", self.styles['CustomBody']))
            story.append(Paragraph(f"<b>Analyst Required:</b> {analyst}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.3*inch))
            
            if malicious > 0:
                story.append(Paragraph("High Priority Issues", self.styles['CustomHeading']))
                for result in scan_results:
                    if result.get('classification') == 'MALICIOUS':
                        story.append(Paragraph(f"- {result.get('url')}", self.styles['CustomBody']))
            
            story.append(Spacer(1, 0.5*inch))
            story.append(Paragraph("Generated by Dr. SSM Eye", self.styles['CustomBody']))
            
            doc.build(story)
            
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            logger.info("Generated batch summary report")
            return pdf_bytes
        
        except Exception as e:
            logger.error(f"Batch report generation error: {e}")
            raise
    
    def generate_batch_detailed_report(self, scan_results: List[Dict[str, Any]]) -> bytes:
        """
        Generate comprehensive batch report
        
        Args:
            scan_results: List of scan result dictionaries
        
        Returns:
            PDF bytes
        """
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            
            summary_bytes = self.generate_batch_summary_report(scan_results)
            
            for i, result in enumerate(scan_results):
                if i > 0:
                    story.append(PageBreak())
                
                url_report_bytes = self.generate_per_url_report(result)
            
            story.append(Spacer(1, 0.5*inch))
            story.append(Paragraph("End of Report", self.styles['CustomBody']))
            
            doc.build(story)
            
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            logger.info("Generated batch detailed report")
            return pdf_bytes
        
        except Exception as e:
            logger.error(f"Batch detailed report error: {e}")
            raise
