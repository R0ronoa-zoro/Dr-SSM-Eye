"""
Dr. SSM Eye - Initial Threat Feed Download Script
"""

from storage.feed_updater import FeedUpdater
from utils.logger import logger


def main():
    logger.info("=" * 60)
    logger.info("Dr. SSM Eye - Initial Feed Download")
    logger.info("=" * 60)
    
    updater = FeedUpdater()
    
    print("\n📥 Downloading threat feeds...")
    print("This may take several minutes...\n")
    
    updater.update_all_feeds()
    
    print("\n✓ Initial feed download complete!")
    print("Feeds will be updated automatically every 24 hours.")


if __name__ == "__main__":
    main()