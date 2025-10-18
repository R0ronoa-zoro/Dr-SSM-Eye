"""
Dr. SSM Eye - Main Entry Point
"""

import sys
import argparse
from pathlib import Path

from ui.app import run_app
from storage.feed_updater import FeedUpdater
from setup_database import setup_database
from utils.logger import logger
from config.settings import VERSION, APP_NAME


def print_banner():
    banner = f"""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║              🔍 Dr. SSM Eye v{VERSION}                    ║
    ║         Advanced Phishing Detection System               ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description=f'{APP_NAME} - Phishing Detection System')
    parser.add_argument('--setup', action='store_true', help='Setup database')
    parser.add_argument('--update-feeds', action='store_true', help='Update threat feeds')
    parser.add_argument('--server', action='store_true', help='Start web server')
    
    args = parser.parse_args()
    
    if args.setup:
        logger.info("Setting up database...")
        success = setup_database()
        if success:
            print("\n✓ Database setup complete!")
        else:
            print("\n✗ Database setup failed!")
            sys.exit(1)
    
    elif args.update_feeds:
        logger.info("Updating threat feeds...")
        updater = FeedUpdater()
        updater.update_all_feeds()
        print("\n✓ Threat feeds updated!")
    
    elif args.server:
        logger.info("Starting web server...")
        run_app()
    
    else:
        parser.print_help()
        print("\nCommon commands:")
        print("  python main.py --setup          # First-time setup")
        print("  python main.py --update-feeds   # Download threat feeds")
        print("  python main.py --server         # Start web interface")


if __name__ == "__main__":
    main()