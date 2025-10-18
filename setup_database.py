"""
Dr. SSM Eye - Database Setup Script
"""

from storage.database import DatabaseManager
from config.settings import DATABASE_PATH
from utils.logger import logger


def setup_database():
    logger.info("Initializing database...")
    
    try:
        db = DatabaseManager(str(DATABASE_PATH))
        logger.info(f"Database created successfully at: {DATABASE_PATH}")
        
        logger.info("Database tables created:")
        logger.info("  - url_scans")
        logger.info("  - malicious_ips")
        logger.info("  - screenshot_metadata")
        logger.info("  - analyst_reviews")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False


if __name__ == "__main__":
    success = setup_database()
    if success:
        print("✓ Database setup complete!")
    else:
        print("✗ Database setup failed!")