from app.db import DatabaseHandler
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db = DatabaseHandler()
class ProjectHandler:
    def __init__(self):
        self.name = None,
        self.url = None


    def save_project(self, name, url):
        try:
            conn = db.get_connection()
            if not conn:
                return False

            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO projects(
                    name, url
                ) VALUES(%s,%s)
            """, (name, url))

            conn.commit()
            cursor.close()
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Error saving project: {e}")
            return False
