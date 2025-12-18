from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import Settings as settings
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from app.config import Config
import json

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseHandler:
    def __init__(self):
        self.connection_params = {
            'host': Config.DB_HOST,
            'port': Config.DB_PORT,
            'database': Config.DB_NAME,
            'user': Config.DB_USER,
            'password': Config.DB_PASSWORD
        }
        self.init_database()

    def get_connection(self):
        """Get database connection"""
        try:
            return psycopg2.connect(**self.connection_params)
        except Exception as e:
            logger.error(f"Database connection error: {str(e)}")
            return None

    def init_database(self):
        """Initialize database and create tables if they don't exist"""
        try:
            conn = self.get_connection()
            if not conn:
                logger.error("Could not connect to database for initialization")
                return

            cursor = conn.cursor()

            # Create notifications table
            cursor.execute("""
                           CREATE TABLE IF NOT EXISTS notification_logs (
                                                                            id SERIAL PRIMARY KEY,
                                                                            device_token VARCHAR(64) NOT NULL,
                               title VARCHAR(255) NOT NULL,
                               message TEXT NOT NULL,
                               badge INTEGER,
                               sound VARCHAR(50),
                               category VARCHAR(100),
                               thread_id VARCHAR(100),
                               custom_data JSONB,
                               priority VARCHAR(10),
                               success BOOLEAN NOT NULL,
                               error_code VARCHAR(100),
                               error_message TEXT,
                               apns_id VARCHAR(100),
                               status_code INTEGER,
                               ip_address VARCHAR(45),
                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                               INDEX idx_device_token (device_token),
                               INDEX idx_created_at (created_at),
                               INDEX idx_success (success)
                               )
                           """)

            conn.commit()
            cursor.close()
            conn.close()

            logger.info("✓ Database initialized successfully")

        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")

    def log_notification(self, device_token, title, message, badge=None, sound=None,
                         category=None, thread_id=None, custom_data=None, priority=None,
                         success=False, error_code=None, error_message=None,
                         apns_id=None, status_code=None, ip_address=None):
        """Log a notification attempt to the database"""
        try:
            conn = self.get_connection()
            if not conn:
                logger.error("Could not connect to database for logging")
                return False

            cursor = conn.cursor()

            # Convert custom_data to JSON string if it's a dict
            custom_data_json = json.dumps(custom_data) if custom_data else None

            cursor.execute("""
                           INSERT INTO notification_logs (
                               device_token, title, message, badge, sound, category,
                               thread_id, custom_data, priority, success, error_code,
                               error_message, apns_id, status_code, ip_address
                           ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                           """, (
                               device_token[:64], title[:255], message, badge, sound,
                               category, thread_id, custom_data_json, priority, success,
                               error_code, error_message, apns_id, status_code, ip_address
                           ))

            conn.commit()
            cursor.close()
            conn.close()

            return True

        except Exception as e:
            logger.error(f"Database logging error: {str(e)}")
            return False

    def get_logs(self, limit=100, offset=0, device_token=None, success=None, start_date=None, end_date=None):
        """Retrieve notification logs with optional filters"""
        try:
            conn = self.get_connection()
            if not conn:
                return None

            cursor = conn.cursor(cursor_factory=RealDictCursor)

            query = "SELECT * FROM notification_logs WHERE 1=1"
            params = []

            if device_token:
                query += " AND device_token = %s"
                params.append(device_token)

            if success is not None:
                query += " AND success = %s"
                params.append(success)

            if start_date:
                query += " AND created_at >= %s"
                params.append(start_date)

            if end_date:
                query += " AND created_at <= %s"
                params.append(end_date)

            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            cursor.execute(query, params)
            logs = cursor.fetchall()

            cursor.close()
            conn.close()

            return logs

        except Exception as e:
            logger.error(f"Error retrieving logs: {str(e)}")
            return None

    def get_stats(self):
        """Get notification statistics"""
        try:
            conn = self.get_connection()
            if not conn:
                return None

            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Total notifications
            cursor.execute("SELECT COUNT(*) as total FROM notification_logs")
            total = cursor.fetchone()['total']

            # Success count
            cursor.execute("SELECT COUNT(*) as success_count FROM notification_logs WHERE success = true")
            success_count = cursor.fetchone()['success_count']

            # Failed count
            cursor.execute("SELECT COUNT(*) as failed_count FROM notification_logs WHERE success = false")
            failed_count = cursor.fetchone()['failed_count']

            # Today's count
            cursor.execute("""
                           SELECT COUNT(*) as today_count
                           FROM notification_logs
                           WHERE DATE(created_at) = CURRENT_DATE
                           """)
            today_count = cursor.fetchone()['today_count']

            # Most common errors
            cursor.execute("""
                           SELECT error_code, COUNT(*) as count
                           FROM notification_logs
                           WHERE success = false AND error_code IS NOT NULL
                           GROUP BY error_code
                           ORDER BY count DESC
                               LIMIT 5
                           """)
            common_errors = cursor.fetchall()

            cursor.close()
            conn.close()

            return {
                'total': total,
                'success': success_count,
                'failed': failed_count,
                'today': today_count,
                'success_rate': round((success_count / total * 100), 2) if total > 0 else 0,
                'common_errors': common_errors
            }

        except Exception as e:
            logger.error(f"Error getting stats: {str(e)}")
            return None