"""
Download threat feeds and cache them locally
Run once, then use cached data
"""

import requests
import json
import zipfile
import io
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


def download_urlhaus():
    """Download URLhaus JSON feed"""
    print("\n📥 Downloading URLhaus feed...")
    
    try:
        url = "https://urlhaus.abuse.ch/downloads/json_online/"
        response = requests.get(url, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract URLs and save
            malicious_urls = []
            for entry_id, entries in data.items():
                if isinstance(entries, list):
                    for entry in entries:
                        if 'url' in entry:
                            malicious_urls.append(entry['url'])
            
            # Save as simple text file
            output_file = DATA_DIR / "urlhaus_cache.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in malicious_urls:
                    f.write(url + '\n')
            
            print(f"✓ URLhaus: {len(malicious_urls)} malicious URLs saved")
            
            # Also save full JSON for reference
            json_file = DATA_DIR / "urlhaus_full.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            print(f"✓ Full JSON saved to: {json_file}")
            
        else:
            print(f"✗ URLhaus download failed: {response.status_code}")
            
    except Exception as e:
        print(f"✗ URLhaus error: {e}")


def download_openphish():
    """Download OpenPhish feed"""
    print("\n📥 Downloading OpenPhish feed...")
    
    try:
        url = "https://openphish.com/feed.txt"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            urls = [line.strip() for line in response.text.split('\n') if line.strip()]
            
            output_file = DATA_DIR / "openphish_cache.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in urls:
                    f.write(url + '\n')
            
            print(f"✓ OpenPhish: {len(urls)} phishing URLs saved")
            
        else:
            print(f"✗ OpenPhish download failed: {response.status_code}")
            
    except Exception as e:
        print(f"✗ OpenPhish error: {e}")


def download_phishtank():
    """Download PhishTank feed (no API key needed for public feed)"""
    print("\n📥 Downloading PhishTank feed...")
    
    try:
        url = "http://data.phishtank.com/data/online-valid.json"
        response = requests.get(url, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            
            urls = [entry['url'] for entry in data if 'url' in entry]
            
            output_file = DATA_DIR / "phishtank_cache.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in urls:
                    f.write(url + '\n')
            
            print(f"✓ PhishTank: {len(urls)} phishing URLs saved")
            
            # Save full JSON
            json_file = DATA_DIR / "phishtank_full.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
        else:
            print(f"✗ PhishTank download failed: {response.status_code}")
            
    except Exception as e:
        print(f"✗ PhishTank error: {e}")


def download_tranco():
    """Download Tranco top 1M list"""
    print("\n📥 Downloading Tranco list...")
    
    # Check if already exists
    if (DATA_DIR / "tranco_top_1m.csv").exists():
        print("✓ Tranco list already exists, skipping download")
        return
    
    try:
        url = "https://tranco-list.eu/top-1m.csv.zip"
        response = requests.get(url, timeout=60)
        
        if response.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                csv_filename = z.namelist()[0]
                with z.open(csv_filename) as f:
                    content = f.read().decode('utf-8')
                    
                    with open(DATA_DIR / "tranco_top_1m.csv", 'w') as out:
                        out.write(content)
            
            # Count lines
            lines = content.split('\n')
            print(f"✓ Tranco: {len(lines)} domains saved")
            
        else:
            print(f"✗ Tranco download failed: {response.status_code}")
            
    except Exception as e:
        print(f"✗ Tranco error: {e}")


def create_combined_database():
    """Combine all feeds into a single database"""
    print("\n🔗 Creating combined threat database...")
    
    all_threats = {
        "urlhaus": [],
        "openphish": [],
        "phishtank": [],
        "last_updated": datetime.now().isoformat()
    }
    
    # Load URLhaus
    urlhaus_file = DATA_DIR / "urlhaus_cache.txt"
    if urlhaus_file.exists():
        with open(urlhaus_file, 'r', encoding='utf-8') as f:
            all_threats["urlhaus"] = [line.strip() for line in f if line.strip()]
    
    # Load OpenPhish
    openphish_file = DATA_DIR / "openphish_cache.txt"
    if openphish_file.exists():
        with open(openphish_file, 'r', encoding='utf-8') as f:
            all_threats["openphish"] = [line.strip() for line in f if line.strip()]
    
    # Load PhishTank
    phishtank_file = DATA_DIR / "phishtank_cache.txt"
    if phishtank_file.exists():
        with open(phishtank_file, 'r', encoding='utf-8') as f:
            all_threats["phishtank"] = [line.strip() for line in f if line.strip()]
    
    # Save combined database
    combined_file = DATA_DIR / "combined_threats.json"
    with open(combined_file, 'w', encoding='utf-8') as f:
        json.dump(all_threats, f, indent=2)
    
    total = len(all_threats["urlhaus"]) + len(all_threats["openphish"]) + len(all_threats["phishtank"])
    print(f"✓ Combined database: {total} total threats")
    print(f"  - URLhaus: {len(all_threats['urlhaus'])}")
    print(f"  - OpenPhish: {len(all_threats['openphish'])}")
    print(f"  - PhishTank: {len(all_threats['phishtank'])}")


def main():
    print("=" * 60)
    print("Dr. SSM Eye - Threat Feed Downloader")
    print("=" * 60)
    print("\nThis will download threat feeds and cache them locally.")
    print("This may take 5-10 minutes depending on your internet speed.")
    print("\nPress Ctrl+C to cancel\n")
    
    input("Press Enter to continue...")
    
    # Download all feeds
    download_urlhaus()
    download_openphish()
    download_phishtank()
    download_tranco()
    
    # Create combined database
    create_combined_database()
    
    print("\n" + "=" * 60)
    print("✓ All feeds downloaded successfully!")
    print("=" * 60)
    print("\nFiles created in data/ folder:")
    print("  - urlhaus_cache.txt")
    print("  - openphish_cache.txt")
    print("  - phishtank_cache.txt")
    print("  - tranco_top_1m.csv")
    print("  - combined_threats.json")
    print("\nYou can now run: python main.py --server")


if __name__ == "__main__":
    main()