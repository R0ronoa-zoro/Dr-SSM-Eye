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
    """Render home page"""
    return render_template('home.html')


@home_bp.route('/scan', methods=['POST'])
def scan_urls():
    """Handle URL scanning requests"""
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
                results.append({
                    'url': result.url,
                    'normalized_url': result.normalized_url,
                    'classification': result.classification,
                    'confidence': result.confidence,
                    'risk_score': result.risk_score,
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


@home_bp.route('/details/<path:url>')
def get_details(url):
    """Get detailed scan information"""
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
    """Serve screenshot images"""
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
    """Generate and download PDF report"""
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
    """Get redirect chain information"""
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