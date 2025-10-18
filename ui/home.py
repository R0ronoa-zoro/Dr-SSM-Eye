"""
Home page - Active scanning workspace
"""

from flask import Blueprint, render_template, request, jsonify, send_file
import logging
from datetime import datetime
import os

from core.scanner import URLScanner
from storage.database import DatabaseManager
from reports.pdf_generator import PDFGenerator

logger = logging.getLogger('dr_ssm_eye')

home_bp = Blueprint('home', __name__)
scanner = URLScanner()
db = DatabaseManager()
pdf_gen = PDFGenerator()


@home_bp.route('/')
def index():
    return render_template('home.html')


@home_bp.route('/scan', methods=['POST'])
def scan_urls():
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        if len(urls) > 25:
            return jsonify({'error': 'Maximum 25 URLs per batch'}), 400
        
        results = []
        for url in urls:
            try:
                result = scanner.scan_url(url)
                
                ip_address = None
                brand_detected = None
                page_title = None
                
                for mod_result in result.module_results:
                    if mod_result.module_name == 'ip_reputation':
                        ip_address = mod_result.features.get('ip')
                    elif mod_result.module_name == 'brand_check':
                        brand_detected = mod_result.features.get('brand_detected')
                    elif mod_result.module_name == 'content':
                        page_title = mod_result.features.get('page_title')
                
                results.append({
                    'url': result.url,
                    'normalized_url': result.normalized_url,
                    'classification': result.classification,
                    'confidence': result.confidence,
                    'risk_score': result.risk_score,
                    'ip_address': ip_address,
                    'brand_detected': brand_detected,
                    'page_title': page_title,
                    'reasoning': [
                        {
                            'feature': r.feature,
                            'description': r.description,
                            'impact': r.impact
                        } for r in result.reasoning
                    ],
                    'screenshot_status': result.screenshot_status,
                    'thumbnail_path': result.screenshot_paths.get('thumbnail', ''),
                    'timestamp': result.timestamp.isoformat()
                })
            except Exception as e:
                logger.error(f"Scan error for {url}: {e}")
                results.append({
                    'url': url,
                    'error': str(e),
                    'classification': 'ERROR'
                })
        
        return jsonify({'results': results})
    
    except Exception as e:
        logger.error(f"Scan endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@home_bp.route('/api/brand-intel/<path:url>')
def get_brand_intel(url):
    try:
        scan_data = db.get_scan_by_url(url)
        
        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404
        
        features = scan_data.get('features', {})
        
        redirect_chain = features.get('redirect_chain', [])
        dest_url = redirect_chain[-1].get('url') if redirect_chain else scan_data.get('url')
        
        intel = {
            'source_url': scan_data.get('url'),
            'dest_url': dest_url,
            'ip_address': features.get('ip_reputation_ip', 'N/A'),
            'status_code': features.get('content_status_code', 'N/A'),
            'body_length': 'N/A',
            'body_sha256': 'N/A',
            'page_title': features.get('content_page_title', 'N/A'),
            'brand_detected': features.get('brand_check_brand_detected', 'None'),
            'is_official': features.get('brand_check_is_official_domain', False),
            'asn': features.get('ip_reputation_asn', 'N/A'),
            'asn_name': features.get('ip_reputation_asn_name', 'N/A'),
            'country': features.get('ip_reputation_country', 'N/A'),
            'ssl_subject': 'N/A',
            'ssl_issuer': features.get('ssl_issuer', 'N/A'),
            'ssl_valid_from': features.get('ssl_valid_from', 'N/A'),
            'ssl_valid_to': features.get('ssl_valid_to', 'N/A'),
            'ssl_validity_period': 'N/A',
            'text_content': 'N/A',
            'domain_age': f"{features.get('whois_domain_age_days', 'Unknown')} days" if features.get('whois_domain_age_days') else 'Unknown',
            'registrar': features.get('whois_registrar', 'N/A'),
            'registration_date': features.get('whois_registration_date', 'N/A'),
            'expiry_date': features.get('whois_expiry_date', 'N/A'),
            'mx_records': ', '.join(features.get('dns_check_mx_records', [])) if features.get('dns_check_mx_records') else 'None',
            'nameservers': ', '.join(features.get('dns_check_nameservers', [])) if features.get('dns_check_nameservers') else 'None',
            'uses_shortener': features.get('redirect_uses_shortener', False),
            'redirect_hops': features.get('redirect_hop_count', 0),
            'has_password_field': features.get('content_has_password_field', False),
            'suspicious_keywords': ', '.join(features.get('content_suspicious_keywords', [])) if features.get('content_suspicious_keywords') else 'None',
            'in_threat_db': features.get('threat_intel_threat_found', False),
            'threat_sources': ', '.join(features.get('threat_intel_sources', [])) if features.get('threat_intel_sources') else 'None',
            'in_whitelist': features.get('whitelist_check_in_whitelist', False),
            'tranco_rank': features.get('whitelist_check_tranco_rank', 'N/A'),
            'requires_manual': scan_data.get('classification') == 'ANALYST_REQUIRED',
            'classification': scan_data.get('classification'),
            'risk_score': scan_data.get('risk_score'),
            'confidence': f"{(scan_data.get('confidence', 0) * 100):.1f}"
        }
        
        return jsonify(intel)
    
    except Exception as e:
        logger.error(f"Brand intel error: {e}")
        return jsonify({'error': str(e)}), 500


@home_bp.route('/details/<path:url>')
def get_details(url):
    try:
        scan_data = db.get_scan_by_url(url)
        
        if not scan_data:
            return "Scan not found", 404
        
        return render_template('details.html', scan=scan_data)
    
    except Exception as e:
        logger.error(f"Details error: {e}")
        return f"Error: {e}", 500


@home_bp.route('/screenshot/<path:filepath>')
def get_screenshot(filepath):
    try:
        full_path = os.path.abspath(os.path.join('storage', 'screenshots', filepath))
        
        if os.path.exists(full_path):
            return send_file(full_path, mimetype='image/png')
        else:
            placeholder = os.path.abspath('assets/placeholder.png')
            if os.path.exists(placeholder):
                return send_file(placeholder, mimetype='image/png')
            return "Image not found", 404
    
    except Exception as e:
        logger.error(f"Screenshot serve error: {e}")
        return "Image not found", 404


@home_bp.route('/download-report/<path:url>')
def download_report(url):
    try:
        scan_data = db.get_scan_by_url(url)
        
        if not scan_data:
            return "Scan not found", 404
        
        pdf_bytes = pdf_gen.generate_per_url_report(scan_data)
        
        filename = f"report_{url.replace('://', '_').replace('/', '_')}.pdf"
        
        from io import BytesIO
        buffer = BytesIO(pdf_bytes)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        logger.error(f"PDF generation error: {e}")
        return f"Error generating report: {e}", 500


@home_bp.route('/redirect-chain/<path:url>')
def get_redirect_chain(url):
    try:
        scan_data = db.get_scan_by_url(url)
        
        if not scan_data:
            return jsonify({'error': 'Scan not found'}), 404
        
        features = scan_data.get('features', {})
        redirect_data = features.get('redirect_chain', [])
        
        return jsonify({'redirects': redirect_data})
    
    except Exception as e:
        logger.error(f"Redirect chain error: {e}")
        return jsonify({'error': str(e)}), 500
