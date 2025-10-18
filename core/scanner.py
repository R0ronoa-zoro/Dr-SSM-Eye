"""
Core Scanner Module
Orchestrates URL scanning workflow
"""

import logging
from typing import List, Optional
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from core.url_normalizer import normalize_url
from core.data_models import ScanResult, Reason
from modules.threat_intel import check_threat_feeds
from modules.whitelist_check import check_whitelist
from modules.brand_check import check_brand_impersonation
from modules.typosquat import detect_typosquatting
from modules.ip_reputation import check_ip_reputation
from modules.dns_check import analyze_dns
from modules.whois_check import check_whois
from modules.ssl_check import check_ssl_certificate
from modules.redirect_check import track_redirects
from modules.content_check import analyze_content
from intelligence.classifier import Classifier
from intelligence.reasoning import ReasoningEngine
from storage.database import DatabaseManager
from visual.screenshot import capture_screenshot
from config.settings import MAX_BULK_UPLOAD, SCAN_TIMEOUT_SECONDS

logger = logging.getLogger('dr_ssm_eye')


class URLScanner:
    """Main URL scanning orchestrator"""
    
    def __init__(self):
        self.classifier = Classifier()
        self.reasoning_engine = ReasoningEngine()
        self.db = DatabaseManager()
        self.logger = logging.getLogger('dr_ssm_eye')
    
    def scan_url(self, url: str) -> ScanResult:
        """
        Scan a single URL
        
        Args:
            url: URL to scan
        
        Returns:
            ScanResult object
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"Scanning URL: {url}")
            
            normalized = normalize_url(url)
            
            if not normalized:
                raise ValueError(f"Invalid URL: {url}")
            
            parsed = urlparse(normalized)
            domain = parsed.netloc
            
            module_results = []
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(check_threat_feeds, normalized): "threat_intel",
                    executor.submit(check_whitelist, domain): "whitelist",
                    executor.submit(check_whois, domain): "whois",
                    executor.submit(analyze_dns, domain): "dns",
                    executor.submit(check_ssl_certificate, domain): "ssl"
                }
                
                for future in as_completed(futures, timeout=SCAN_TIMEOUT_SECONDS):
                    try:
                        result = future.result()
                        if result:
                            module_results.append(result)
                    except Exception as e:
                        module_name = futures[future]
                        self.logger.error(f"Module {module_name} failed: {e}")
            
            try:
                typo_result = detect_typosquatting(domain)
                if typo_result:
                    module_results.append(typo_result)
            except Exception as e:
                self.logger.error(f"Typosquatting check failed: {e}")
            
            try:
                ip_result = check_ip_reputation(domain)
                if ip_result:
                    module_results.append(ip_result)
            except Exception as e:
                self.logger.error(f"IP reputation check failed: {e}")
            
            try:
                redirect_result = track_redirects(normalized)
                if redirect_result:
                    module_results.append(redirect_result)
            except Exception as e:
                self.logger.error(f"Redirect tracking failed: {e}")
            
            try:
                content_result = analyze_content(normalized)
                if content_result:
                    module_results.append(content_result)
            except Exception as e:
                self.logger.error(f"Content analysis failed: {e}")
            
            screenshot_path = ""
            try:
                screenshot_data = capture_screenshot(normalized)
                if screenshot_data:
                    screenshot_path = screenshot_data.get('full', '')
            except Exception as e:
                self.logger.error(f"Screenshot capture failed: {e}")
            
            try:
                brand_result = check_brand_impersonation(
                    normalized,
                    content_result.features.get('page_title', '') if content_result else '',
                    None,
                    screenshot_path
                )
                if brand_result:
                    module_results.append(brand_result)
            except Exception as e:
                self.logger.error(f"Brand check failed: {e}")
            
            features = self.classifier.aggregate_features(module_results)
            
            risk_score = self.classifier.calculate_risk_score(features, module_results)
            
            adjusted_score, context_note = self.reasoning_engine.apply_context_rules(
                features, risk_score, module_results
            )
            
            classification, confidence = self.classifier.classify(
                features, module_results, adjusted_score
            )
            
            brand_detected = None
            for result in module_results:
                if result and result.module_name == "brand_check":
                    brand_detected = result.features.get('brand_detected')
                    break
            
            reasoning = self.reasoning_engine.generate_reasoning(
                features, module_results, adjusted_score, classification, brand_detected
            )
            
            scan_duration = time.time() - start_time
            
            screenshot_status = "ready" if screenshot_path else "failed"
            screenshot_paths = {
                'thumbnail': screenshot_path.replace('/full/', '/thumbnails/') if screenshot_path else '',
                'full': screenshot_path
            }
            
            scan_result = ScanResult(
                url=url,
                normalized_url=normalized,
                classification=classification,
                confidence=confidence,
                risk_score=adjusted_score,
                reasoning=reasoning,
                features=features,
                screenshot_status=screenshot_status,
                screenshot_paths=screenshot_paths,
                timestamp=datetime.now(),
                scan_duration=scan_duration
            )
            
            try:
                self.db.save_scan(scan_result)
            except Exception as e:
                self.logger.error(f"Failed to save scan to database: {e}")
            
            self.logger.info(
                f"Scan complete: {url} - {classification} ({confidence:.0%})"
            )
            
            return scan_result
        
        except Exception as e:
            self.logger.error(f"Scan error for {url}: {e}")
            
            return ScanResult(
                url=url,
                normalized_url=url,
                classification="ERROR",
                confidence=0.0,
                risk_score=0,
                reasoning=[Reason(
                    feature="error",
                    value=str(e),
                    points=0,
                    impact="negative",
                    description=f"Scan failed: {str(e)}"
                )],
                features={"error": str(e)},
                screenshot_status="failed",
                screenshot_paths={},
                timestamp=datetime.now(),
                scan_duration=time.time() - start_time
            )
    
    def scan_bulk(self, urls: List[str]) -> List[ScanResult]:
        """
        Scan multiple URLs
        
        Args:
            urls: List of URLs to scan
        
        Returns:
            List of ScanResult objects
        """
        if len(urls) > MAX_BULK_UPLOAD:
            self.logger.warning(f"Bulk upload exceeds limit: {len(urls)} > {MAX_BULK_UPLOAD}")
            urls = urls[:MAX_BULK_UPLOAD]
        
        results = []
        
        for url in urls:
            try:
                result = self.scan_url(url)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Bulk scan error for {url}: {e}")
                results.append(ScanResult(
                    url=url,
                    normalized_url=url,
                    classification="ERROR",
                    confidence=0.0,
                    risk_score=0,
                    reasoning=[],
                    features={"error": str(e)},
                    screenshot_status="failed",
                    screenshot_paths={},
                    timestamp=datetime.now(),
                    scan_duration=0.0
                ))
        
        return results