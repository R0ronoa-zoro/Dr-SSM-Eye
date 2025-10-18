"""
Dr. SSM Eye - Configuration and Settings
=========================================
Central configuration file for all system settings, thresholds, and paths.
"""

import os
from pathlib import Path

# ============================================================================
# PROJECT PATHS
# ============================================================================

# Base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent

# Data directories
DATA_DIR = BASE_DIR / "data"
ASSETS_DIR = BASE_DIR / "assets"
STORAGE_DIR = BASE_DIR / "storage"
SCREENSHOTS_DIR = STORAGE_DIR / "screenshots"
THUMBNAILS_DIR = SCREENSHOTS_DIR / "thumbnails"
FULL_SCREENSHOTS_DIR = SCREENSHOTS_DIR / "full"

# Template directories
TEMPLATES_DIR = BASE_DIR / "reports" / "templates"

# Database path
DATABASE_PATH = STORAGE_DIR / "scan_history.db"

# Brand database
BRANDS_JSON_PATH = DATA_DIR / "brands.json"

# Asset paths
BRAND_FAVICONS_PATH = ASSETS_DIR / "favicons"
BRAND_LOGOS_PATH = ASSETS_DIR / "logos"
BRAND_SCREENSHOTS_PATH = ASSETS_DIR / "screenshots"

# Ensure directories exist
for directory in [DATA_DIR, ASSETS_DIR, STORAGE_DIR, SCREENSHOTS_DIR, 
                  THUMBNAILS_DIR, FULL_SCREENSHOTS_DIR, TEMPLATES_DIR,
                  BRAND_FAVICONS_PATH, BRAND_LOGOS_PATH, BRAND_SCREENSHOTS_PATH]:
    directory.mkdir(parents=True, exist_ok=True)


# ============================================================================
# API KEYS & CREDENTIALS
# ============================================================================

# PhishTank (10K requests/hour, free)
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")  # Optional, can work without key

# Google Safe Browsing (10K requests/day)
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

# URLhaus (unlimited, free - no key needed)
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/"

# OpenPhish (unlimited, free - no key needed)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


# ============================================================================
# THREAT FEED SETTINGS
# ============================================================================

# Update intervals
UPDATE_FEEDS_INTERVAL_HOURS = 24  # Daily updates

# Feed URLs
PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.csv"
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Cache settings
THREAT_FEED_MAX_AGE_DAYS = 90  # Delete entries older than 90 days
THREAT_FEED_CACHE_SIZE = 100000  # Max entries to keep in memory


# ============================================================================
# TRANCO WHITELIST SETTINGS
# ============================================================================

# Tranco list URL
TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Update interval
TRANCO_UPDATE_INTERVAL_DAYS = 7  # Weekly updates

# List sizes
TRANCO_TOP_N = 1000000  # Download top 1M
TRANCO_TOP_10K = 10000  # Load top 10K in memory
TRANCO_TOP_100K = 100000  # Load top 100K in memory

# Local cache path
TRANCO_CACHE_PATH = DATA_DIR / "tranco_top_1m.csv"


# ============================================================================
# SCREENSHOT SETTINGS
# ============================================================================

# Timeouts
SCREENSHOT_TIMEOUT_SECONDS = 10  # Max time to capture screenshot

# Viewport settings
SCREENSHOT_VIEWPORT_WIDTH = 800
SCREENSHOT_VIEWPORT_HEIGHT = 600

# Thumbnail settings
THUMBNAIL_SIZE = (100, 75)  # Width x Height
THUMBNAIL_QUALITY = 75  # JPEG quality (1-100)

# Concurrency
MAX_CONCURRENT_SCREENSHOTS = 2  # Max parallel screenshot captures

# Browser settings
HEADLESS_BROWSER = True  # Run browser in headless mode
DISABLE_IMAGES = False  # Set to True for faster captures (no images)

# Screenshot storage
MAX_SCREENSHOT_AGE_DAYS = 30  # Delete screenshots older than 30 days
MAX_SCREENSHOT_STORAGE_GB = 2  # Max storage for screenshots (2GB)


# ============================================================================
# SCAN SETTINGS
# ============================================================================

# Limits
MAX_BULK_UPLOAD = 25  # Max URLs per bulk upload
MAX_TOTAL_URLS = 200  # Max total URLs in database (personal project limit)

# Timeouts
SCAN_TIMEOUT_SECONDS = 30  # Max time for single URL scan
HTTP_REQUEST_TIMEOUT = 10  # HTTP request timeout
DNS_TIMEOUT = 5  # DNS query timeout
WHOIS_TIMEOUT = 10  # WHOIS query timeout

# Redirects
MAX_REDIRECT_HOPS = 5  # Max redirects to follow

# Parallelization
MAX_PARALLEL_SCANS = 3  # Max concurrent URL scans
MAX_PARALLEL_MODULES = 5  # Max concurrent module executions per scan


# ============================================================================
# SCORING THRESHOLDS
# ============================================================================

# Classification thresholds
CLEAN_THRESHOLD = -20  # Score below this = CLEAN
SUSPICIOUS_THRESHOLD = 40  # Score -20 to 40 = SUSPICIOUS
MALICIOUS_THRESHOLD = 40  # Score above 40 = MALICIOUS

# Confidence thresholds
ANALYST_REQUIRED_CONFIDENCE = 0.60  # Below 60% confidence = ANALYST_REQUIRED
HIGH_CONFIDENCE = 0.85  # Above 85% = high confidence
LOW_CONFIDENCE = 0.50  # Below 50% = low confidence

# Risk score limits
MIN_RISK_SCORE = -100  # Minimum risk score (very safe)
MAX_RISK_SCORE = 200  # Maximum risk score (very dangerous)


# ============================================================================
# MODULE SCORING WEIGHTS
# ============================================================================

# Threat Intelligence
THREAT_FEED_PHISHTANK_POINTS = 50
THREAT_FEED_URLHAUS_POINTS = 50
THREAT_FEED_OPENPHISH_POINTS = 50
THREAT_FEED_GOOGLE_SB_POINTS = 50

# Whitelist
WHITELIST_TOP_10K_POINTS = -50  # Very trusted
WHITELIST_TOP_100K_POINTS = -20  # Trusted
WHITELIST_TOP_1M_POINTS = -5  # Known site

# Brand Impersonation
BRAND_OFFICIAL_DOMAIN_POINTS = -40  # Legitimate
BRAND_TYPOSQUAT_POINTS = 25
BRAND_FAVICON_MATCH_POINTS = 40
BRAND_LOGO_HEADER_POINTS = 35
BRAND_LOGO_FOOTER_POINTS = 15  # Likely payment integration
BRAND_LAYOUT_SIMILAR_POINTS = 25
BRAND_TITLE_MATCH_POINTS = 10

# Context adjustments
FAVICON_MISMATCH_ADJUSTMENT = -40  # Own favicon (likely legitimate)
OLD_DOMAIN_ADJUSTMENT = -25  # Domain age >3 years
BUSINESS_SSL_ADJUSTMENT = -15

# Domain Age
DOMAIN_AGE_VERY_NEW_POINTS = 30  # <7 days
DOMAIN_AGE_NEW_POINTS = 20  # 7-30 days
DOMAIN_AGE_RECENT_POINTS = 10  # 30-365 days
DOMAIN_AGE_NEUTRAL_POINTS = 0  # 1-3 years
DOMAIN_AGE_ESTABLISHED_POINTS = -30  # >3 years

# SSL Certificate
SSL_NO_HTTPS_POINTS = 10
SSL_SELF_SIGNED_POINTS = 25
SSL_VERY_NEW_POINTS = 15  # <7 days
SSL_NEW_POINTS = 10  # 7-30 days
SSL_OLD_POINTS = -20  # >1 year
SSL_COMMERCIAL_CA_POINTS = -15

# IP Reputation
IP_PRIVATE_POINTS = -50  # Private IP (safe)
IP_MALICIOUS_FRESH_POINTS = 50  # <7 days
IP_MALICIOUS_RECENT_POINTS = 30  # <30 days
IP_MALICIOUS_OLD_POINTS = 15  # <90 days
IP_SUSPICIOUS_ASN_POINTS = 30

# DNS Analysis
DNS_NO_A_RECORD_POINTS = 20  # Doesn't resolve
DNS_NO_MX_RECORDS_POINTS = 10  # No email
DNS_HAS_MX_RECORDS_POINTS = -10  # Has email
DNS_REPUTABLE_NS_POINTS = -5
DNS_SKETCHY_NS_POINTS = 15
DNS_SLOW_RESPONSE_POINTS = 10  # >2 seconds

# WHOIS
WHOIS_PRIVACY_POINTS = 5
WHOIS_SKETCHY_REGISTRAR_POINTS = 15

# Redirects
REDIRECT_1_2_HOPS_POINTS = 5
REDIRECT_3_4_HOPS_POINTS = 15
REDIRECT_5_PLUS_HOPS_POINTS = 25
REDIRECT_URL_SHORTENER_POINTS = 15
REDIRECT_DIFFERENT_DOMAIN_POINTS = 10

# Content Analysis
CONTENT_PASSWORD_FIELD_POINTS = 20
CONTENT_SUSPICIOUS_KEYWORD_POINTS = 10  # Per keyword
CONTENT_NO_META_TAGS_POINTS = 5
CONTENT_EXCESSIVE_RESOURCES_POINTS = 15  # >50 external resources
CONTENT_JS_OBFUSCATION_POINTS = 20
CONTENT_PROPER_META_POINTS = -5
CONTENT_LOW_RESOURCES_POINTS = -5


# ============================================================================
# BRAND DETECTION SETTINGS
# ============================================================================

# Favicon matching
MIN_FAVICON_MATCH_DISTANCE = 5  # Perceptual hash distance (lower = better match)
FAVICON_EXACT_MATCH_DISTANCE = 2  # Distance 0-2 = exact match
FAVICON_SIMILAR_MATCH_DISTANCE = 5  # Distance 3-5 = similar

# Logo detection
MIN_LOGO_CONFIDENCE = 0.6  # Minimum confidence for logo detection (60%)
LOGO_HEADER_Y_THRESHOLD = 200  # Y-coordinate <200px = header
LOGO_FOOTER_Y_THRESHOLD = 400  # Y-coordinate >400px = footer
LOGO_PRIMARY_SIZE_THRESHOLD = 0.20  # >20% viewport = primary branding
LOGO_SMALL_SIZE_THRESHOLD = 0.05  # <5% viewport = payment option

# Visual similarity
MIN_VISUAL_SIMILARITY = 0.85  # 85% similarity threshold for layout matching
HIGH_VISUAL_SIMILARITY = 0.90  # 90%+ = very similar
MODERATE_VISUAL_SIMILARITY = 0.75  # 75-85% = somewhat similar

# Typosquatting
TYPOSQUAT_HIGH_SIMILARITY = 0.90  # 90-100% = obvious typosquat
TYPOSQUAT_MEDIUM_SIMILARITY = 0.80  # 80-89% = likely typosquat
TYPOSQUAT_LOW_SIMILARITY = 0.70  # 70-79% = possible typosquat

TYPOSQUAT_HIGH_POINTS = 30
TYPOSQUAT_MEDIUM_POINTS = 20
TYPOSQUAT_LOW_POINTS = 10


# ============================================================================
# CACHING SETTINGS
# ============================================================================

# Cache TTLs (Time To Live)
CACHE_WHOIS_DAYS = 7  # WHOIS data valid for 7 days
CACHE_DNS_HOURS = 24  # DNS data valid for 24 hours
CACHE_IP_REPUTATION_HOURS = 12  # IP reputation valid for 12 hours
CACHE_SSL_DAYS = 7  # SSL cert data valid for 7 days

# In-memory cache sizes
WHOIS_CACHE_SIZE = 1000  # Max WHOIS entries in memory
DNS_CACHE_SIZE = 5000  # Max DNS entries in memory
IP_CACHE_SIZE = 10000  # Max IP entries in memory


# ============================================================================
# DATABASE SETTINGS
# ============================================================================

# SQLite settings
DATABASE_POOL_SIZE = 10  # Connection pool size
DATABASE_TIMEOUT = 30  # Database lock timeout (seconds)

# Cleanup settings
DATABASE_CLEANUP_INTERVAL_DAYS = 30  # Run cleanup every 30 days
DATABASE_MAX_SCAN_AGE_DAYS = 365  # Delete scans older than 1 year


# ============================================================================
# PERFORMANCE SETTINGS
# ============================================================================

# Resource limits
MAX_MEMORY_MB = 400  # Max RAM usage (300-400MB peak)
MAX_STORAGE_GB = 3.5  # Max storage usage

# Optimization flags
ENABLE_PARALLEL_EXECUTION = True  # Enable parallel module execution
ENABLE_CACHING = True  # Enable result caching
ENABLE_COMPRESSION = True  # Compress stored data

# Rate limiting
MAX_REQUESTS_PER_MINUTE = 60  # Max external API requests per minute


# ============================================================================
# ML MODEL SETTINGS
# ============================================================================

# Model path
ML_MODEL_PATH = DATA_DIR / "xgboost_model.pkl"

# Model parameters (for training)
ML_MAX_DEPTH = 6
ML_LEARNING_RATE = 0.1
ML_N_ESTIMATORS = 100
ML_OBJECTIVE = "multi:softprob"  # Multi-class classification

# Feature count
ML_FEATURE_COUNT = 23  # Total features for classification

# Training settings
ML_TRAIN_TEST_SPLIT = 0.8  # 80% train, 20% test
ML_RANDOM_STATE = 42


# ============================================================================
# LOGGING SETTINGS
# ============================================================================

# Log levels
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE_PATH = BASE_DIR / "logs" / "dr_ssm_eye.log"
LOG_MAX_SIZE_MB = 10  # Max log file size before rotation
LOG_BACKUP_COUNT = 5  # Number of backup log files to keep

# Create logs directory
LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)


# ============================================================================
# UI SETTINGS
# ============================================================================

# Flask/FastAPI settings
UI_HOST = "127.0.0.1"
UI_PORT = 5000
UI_DEBUG = True  # Set to False in production

# Pagination
RESULTS_PER_PAGE = 10  # Results per page in EyeSight

# Session settings
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
SESSION_TIMEOUT_MINUTES = 60


# ============================================================================
# REPORT SETTINGS
# ============================================================================

# PDF settings
PDF_PAGE_SIZE = "A4"
PDF_ORIENTATION = "portrait"
PDF_FONT_FAMILY = "Arial"

# Report types
REPORT_TYPE_PER_URL = "per_url"
REPORT_TYPE_BATCH_SUMMARY = "batch_summary"
REPORT_TYPE_BATCH_DETAILED = "batch_detailed"


# ============================================================================
# SUSPICIOUS KEYWORDS (for content analysis)
# ============================================================================

SUSPICIOUS_KEYWORDS = [
    "verify", "urgent", "suspended", "limited time", "act now",
    "confirm", "update", "secure", "authenticate", "validate",
    "expire", "immediately", "click here", "account", "password",
    "credit card", "social security", "ssn", "tax", "refund",
    "winner", "prize", "lottery", "inheritance", "claim",
    "security alert", "unusual activity", "locked", "restricted"
]


# ============================================================================
# URL SHORTENER DOMAINS (for redirect detection)
# ============================================================================

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "buff.ly", "is.gd", "tiny.cc", "shorte.st", "adf.ly",
    "bc.vc", "budurl.com", "clck.ru", "cli.gs", "cutt.ly",
    "short.link", "s.id", "rebrand.ly", "bl.ink", "lnkd.in"
]


# ============================================================================
# SUSPICIOUS TLDs (Top-Level Domains)
# ============================================================================

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs (often abused)
    ".cc", ".pw", ".top", ".xyz", ".work",
    ".click", ".link", ".download", ".stream", ".racing"
]


# ============================================================================
# REPUTABLE NAMESERVERS
# ============================================================================

REPUTABLE_NAMESERVERS = [
    "cloudflare", "amazon", "google", "azure", "route53",
    "ns1.com", "dnsimple", "dnsmadeeasy", "godaddy", "namecheap"
]


# ============================================================================
# SKETCHY REGISTRARS (known for abuse)
# ============================================================================

SKETCHY_REGISTRARS = [
    "namecheap", "hostinger", "domains by proxy",  # Privacy services
    "perfect privacy", "whoisguard", "id shield"
]


# ============================================================================
# CONTEXT RULES THRESHOLDS
# ============================================================================

# Payment integration detection
PAYMENT_INTEGRATION_DOMAIN_AGE_MIN = 365  # >1 year old
PAYMENT_INTEGRATION_SCORE_REDUCTION = 60

# Ambiguous case detection
AMBIGUOUS_VISUAL_SIMILARITY_MIN = 0.75
AMBIGUOUS_MIXED_SIGNALS_THRESHOLD = 3  # Number of contradicting signals

# Whitelisted with suspicious features
WHITELISTED_SUSPICIOUS_MAX_SCORE = 20  # Cap at SUSPICIOUS level

# New legitimate business
NEW_BUSINESS_DOMAIN_AGE_MAX = 30  # <30 days
NEW_BUSINESS_PENALTY_REDUCTION = 0.5  # Reduce penalty by 50%


# ============================================================================
# VERSION INFO
# ============================================================================

VERSION = "1.0.0"
APP_NAME = "Dr. SSM Eye"
APP_DESCRIPTION = "Advanced Phishing Detection System"
AUTHOR = "SSM Security"
LICENSE = "MIT"


# ============================================================================
# FEATURE FLAGS
# ============================================================================

# Enable/disable features
ENABLE_SCREENSHOT_CAPTURE = True
ENABLE_LOGO_DETECTION = True
ENABLE_ML_CLASSIFICATION = True
ENABLE_VISUAL_SIMILARITY = True
ENABLE_THREAT_FEEDS = True
ENABLE_BRAND_DETECTION = True

# Development flags
SKIP_SLOW_MODULES = False  # Skip slow modules for testing
USE_MOCK_DATA = False  # Use mock data for testing