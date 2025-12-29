from app.db import DatabaseHandler
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
db = DatabaseHandler()

class CompanyHandler:
    def __init__(self):
        self.name = None
        self.address = None
        self.phone = None
        self.email = None
        self.url = None

    def save_company(
            self,
            name,
            address,
            phone,
            email,
            url
    ):
        try:
            conn = db.get_connection()
            if not conn:
                return False

            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO companies (
                    name, address, phone, email, url
                ) VALUES(%s,%s,%s,%s,%s)
            """, (name, address, phone, email, url))
            conn.commit()
            cursor.close()
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Error saving Company: {e}")
            return False


    def assign_key(self, company_id,key_id):
        try:
            conn = db.get_connection()
            if not conn:
                return False

            cursor = conn.cursor()
            cursor.execute("""
                 UPDATE apn_keys set company_id = %s where key_id = %s
            """,(company_id,key_id))

            conn.commit()
            cursor.close()
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Error assigning Company to a Key: {e} ")
            return False