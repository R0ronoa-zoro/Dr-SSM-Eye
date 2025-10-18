# Dr. SSM Eye - Advanced Phishing Detection System

## Overview

Dr. SSM Eye is a multi-layered phishing detection system that analyzes URLs using 8+ detection modules, visual analysis, and machine learning to classify threats as Clean, Suspicious, Malicious, or requiring Analyst review. Every classification includes explainable reasoning showing exactly why a verdict was reached.

**Status:** Design Complete | Implementation Ready  
**Target Accuracy:** 95%+ with <2% false positives

## Core Problem

Simple scanners fail on sophisticated attacks:
- Brand impersonation with old domains (google.com-verify.net.com)
- Typosquatting with stolen visual assets (paypa1-secure.com)
- Legitimate payment integrations vs actual phishing (ambiguous signals)

## Solution Architecture
Input URL → Parallel Checks → Weighted Scoring → ML Classification → Explainable Output

**Detection Pipeline:**
1. Instant checks (whitelist, threat feeds)
2. Feature extraction (23 lightweight features)
3. Context-aware scoring (weighted combination of signals)
4. Visual analysis (screenshots, favicon/logo matching)
5. Reasoning engine (point-by-point breakdown)

## Key Capabilities

**Detection Modules:**
- Threat Intelligence (PhishTank, URLhaus, OpenPhish, Google Safe Browsing)
- Brand Verification (600+ global brands with asset matching)
- Typosquatting Detection (character substitution, homographs)
- IP Reputation (custom database from threat feeds + ASN tracking)
- Visual Analysis (screenshot comparison, perceptual hashing)
- Redirect Chain Tracking (up to 5 hops)
- SSL Certificate Validation
- Content Analysis (login forms, keywords, page structure)
- DNS Intelligence (A, MX, NS records)
- WHOIS Lookup (domain age, registrar)

**Smart Features:**
- URL normalization (google.com = www.google.com = https://google.com)
- Private IP handling (192.168.x.x treated as safe)
- Context-aware brand detection (payment integration vs impersonation)
- Four-tier classification (Clean/Suspicious/Malicious/Analyst Required)
- Graceful error handling (WHOIS/DNS failures don't break analysis)

## Tech Stack

**Core:**
- Python 3.10+
- XGBoost (ML classification)
- SQLite + JSON (hybrid storage)

**Libraries:**
- Detection: dnspython, python-whois, requests, beautifulsoup4, ipwhois
- ML: xgboost, scikit-learn, pandas, numpy
- Visual: playwright, Pillow, imagehash, opencv-python
- Reporting: WeasyPrint

**Data Sources (Free):**
- PhishTank, URLhaus, OpenPhish (threat feeds)
- Google Safe Browsing (10K requests/day)
- Tranco List (top 1M legitimate sites)

## Resource Specifications

- RAM: 300-400MB peak
- Storage: <3.5GB total (dataset 2-3GB, assets 15MB, screenshots 41MB)
- Performance: <300ms per URL (without screenshot), 2-4 sec with screenshot
- Scale: 200 URLs max (personal project scope), 25 per bulk upload

## User Interface

**Two-Page Structure:**

**Home (Active Workspace):**
- URL input or bulk upload (25 max, one per line)
- 2x5 grid layout (10 cards per page)
- Real-time scanning with async screenshot loading
- Multi-select with checkboxes

**EyeSight (Historical Database):**
- All previously scanned URLs
- Filters: tags, keywords, date range
- Sort: latest to oldest
- Re-scan functionality with history tracking

**Color Coding:**
- Green: Clean
- Orange: Suspicious
- Red: Malicious
- White: Undefined/Not scanned

**Card Display:**
- Thumbnail screenshot (100x75px)
- Classification + confidence + risk score
- Source URL + Destination URL (after redirects)
- IP address, brand detected, page title
- Actions: Brand Intel, Takedown, Detailed View

## Classification System

**Four Tiers:**

1. CLEAN - High confidence legitimate (e.g., google.com)
2. SUSPICIOUS - Mixed signals, borderline case (e.g., new domain with some red flags)
3. MALICIOUS - Clear phishing/malicious intent (e.g., brand impersonation, in threat feeds)
4. ANALYST REQUIRED - Conflicting signals, uncertain (e.g., e-commerce with PayPal integration)

**Reasoning Engine:**
Every classification includes risk score breakdown, feature contributions, evidence summary, confidence percentage, and recommendation.

## Brand Database

**Coverage: 600+ Global Brands**

**Regions:**
- ASEAN (100): Singapore, Malaysia, Indonesia, Thailand, Philippines, Vietnam
- North America (100): US, Canada, Mexico
- Europe & UK (100): Major European countries
- South America (100): Brazil, Argentina, Chile, Colombia, Peru
- ANZ (100): Australia, New Zealand, Pacific
- Russia (100): Banks, telecom, tech
- Asia: India, Bangladesh, China, Japan, South Korea
- META: Middle East, Turkey, Africa

**Categories:**
- Government (100+): Tax agencies, postal services, immigration
- Financial (100+): Banks, payment processors, crypto exchanges

**Per-Brand Assets:**
- Official domains
- Favicon with perceptual hash
- Logo with perceptual hash
- Common typosquatting variations
- Keywords

## Feature Engineering

**23 Lightweight Features:**

URL String (10): length, subdomain count, special characters, IP address, suspicious TLD, entropy, brand names, URL shortener

Domain Intelligence (8): age, whitelist status, blacklist status, TLD reputation, HTTPS, certificate age, subdomain patterns, port

Content (5): response time, page title, password fields, external resources, favicon match

**Scoring System:**
Risk score range: -100 (safe) to +200 (dangerous)

Major indicators:
- +50: In threat database
- +40: Favicon matches target brand
- +30: Domain <30 days old
- +25: URL impersonates brand
- -50: In Tranco Top 10K
- -30: Domain >3 years old

Thresholds:
- <-20: CLEAN
- -20 to 40: SUSPICIOUS
- >40: MALICIOUS
- Confidence <60%: ANALYST REQUIRED

## Screenshot System

**Two-Tier Approach:**
- Thumbnail (100x75px, ~5KB): Grid view, fast loading
- Full size (800x600px, ~200KB): Detailed modal view

**Async Processing:**
- ML analysis completes instantly
- Screenshots load progressively (non-blocking)
- Loading spinners during capture

**Visual Brand Comparison:**
For suspected impersonation, shows side-by-side comparison with legitimate brand site, perceptual hash similarity percentage, and logo position analysis.

## Reporting

**Three PDF Report Types (generated on-demand):**

1. Per-URL Detailed Report (5-10 pages): Full analysis, screenshots, technical details, threat intelligence, takedown info
2. Batch Summary Report (2-3 pages): Overview statistics, high-priority issues, recommendations
3. Batch Detailed Report (50+ pages): Comprehensive analysis for all URLs in batch

Generated in memory, immediate download, no disk storage.

## Data Storage

**Hybrid Approach:**

SQLite (scan_history.db):
- url_scans (results, classifications, scores)
- malicious_ips (threat feed IPs + ASN)
- screenshot_metadata (paths, hashes)

JSON Files:
- brands.json (brand metadata)
- tranco_top_1m.csv (whitelist)

File Storage:
- assets/ (brand favicons, logos, legitimate screenshots)
- screenshots/ (thumbnails, full size captures)

## Workflow

**Single URL Scan:**
1. User enters URL
2. Instant analysis (100ms): normalization, checks, feature extraction, classification
3. Results display: classification, confidence, risk score, reasons, loading spinner
4. Screenshot loads (2-3 sec): thumbnail appears, full size on click
5. Detailed view: full analysis popup, comparisons, export option

**Bulk Upload:**
1. Paste URLs (max 25, one per line)
2. Validation feedback
3. Progressive processing: cards appear, classifications complete, screenshots load progressively
4. Batch reports available
5. Multi-select actions, clear moves to EyeSight

**EyeSight:**
1. Historical scans with filters
2. Re-scan updates existing entry (no duplicates)
3. Shows scan history and status changes
4. Same detailed view as Home

## License

Personal Project (Current Scope)
Key Contributor: Manasi Jha, Claude AI