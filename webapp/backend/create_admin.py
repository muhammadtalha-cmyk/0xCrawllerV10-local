import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.database import Database, utc_now
from app.config import settings
from app.auth import get_password_hash

def create_admin(username, password):
    db = Database(settings.database_path, settings.database_url)
    
    placeholder = "%s" if db.is_postgres else "?"
    user = db.query_one(f"SELECT id FROM users WHERE username = {placeholder}", (username,))
    
    if user:
        print(f"User '{username}' already exists.")
        return

    user_id = str(uuid.uuid4())
    hashed_pw = get_password_hash(password)
    now = utc_now()
    
    db.execute(
        f"""
        INSERT INTO users(id, username, password_hash, role, created_at)
        VALUES({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
        """,
        (user_id, username, hashed_pw, "ADMIN", now)
    )
    print(f"Created admin user '{username}'.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python create_admin.py <username> <password>")
        sys.exit(1)
    
    create_admin(sys.argv[1], sys.argv[2])
