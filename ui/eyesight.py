"""
EyeSight page - Historical scan database
"""

from flask import Blueprint, render_template, request, jsonify, send_file
import logging
from datetime import datetime, timedelta

from storage.database import DatabaseManager
from core.scanner import URLScanner
from reports.pdf_generator import PDFGenerator

logger = logging.getLogger('dr_ssm_eye')

eyesight_bp = Blueprint('eyesight', __name__)
db = DatabaseManager()
scanner = URLScanner()
pdf_gen = PDFGenerator()


@eyesight_bp.route('/eyesight')
def index():
    """Render eyesight page"""
    return render_template('eyesight.html')


@eyesight_bp.route('/api/scans')
def get_scans():
    """Get all scans with filters"""
    try:
        classification = request.args.get('classification', 'all')
        search = request.args.get('search', '')
        date_range = request.args.get('date_range', 'all')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        filters = {}
        
        if classification != 'all':
            filters['classification'] = classification
        
        if search:
            filters['search'] = search
        
        if date_range != 'all':
            if date_range == 'today':
                filters['after'] = datetime.now().replace(hour=0, minute=0, second=0)
            elif date_range == 'week':
                filters['after'] = datetime.now() - timedelta(days=7)
            elif date_range == 'month':
                filters['after'] = datetime.now() - timedelta(days=30)
        
        scans = db.get_all_scans(filters=filters, limit=per_page, offset=(page-1)*per_page)
        total = db.count_scans(filters=filters)
        
        return jsonify({
            'scans': scans,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
    
    except Exception as e:
        logger.error(f"Get scans error: {e}")
        return jsonify({'error': str(e)}), 500


@eyesight_bp.route('/api/rescan/<path:url>', methods=['POST'])
def rescan_url(url):
    """Re-scan an existing URL"""
    try:
        result = scanner.scan_url(url)
        
        return jsonify({
            'success': True,
            'url': result.url,
            'classification': result.classification,
            'confidence': result.confidence,
            'risk_score': result.risk_score
        })
    
    except Exception as e:
        logger.error(f"Re-scan error for {url}: {e}")
        return jsonify({'error': str(e)}), 500


@eyesight_bp.route('/api/delete/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan record"""
    try:
        db.delete_scan(scan_id)
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Delete scan error: {e}")
        return jsonify({'error': str(e)}), 500