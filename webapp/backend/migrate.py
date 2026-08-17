import os
import sys
from pathlib import Path

# Add the backend directory to python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.config import settings
from app.database import Database

def migrate_database():
    print(f"Migrating database. Mode: {'PostgreSQL' if settings.database_url else 'SQLite'}")
    db = Database(settings.database_path, settings.database_url)
    
    with db._write_lock, db.connect() as connection:
        if db.is_postgres:
            # PostgreSQL migrations
            print("Applying PostgreSQL migrations...")
            with connection.cursor() as cursor:
                # Create users table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'USER',
                        created_at TEXT NOT NULL
                    )
                """)
                
                # Add user_id to scans if not exists
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='scans' AND column_name='user_id'
                """)
                if not cursor.fetchone():
                    print("Adding user_id to scans...")
                    cursor.execute("ALTER TABLE scans ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL")
                
                # Add cloudinary_url and cloudinary_public_id to artifacts
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='artifacts' AND column_name='cloudinary_url'
                """)
                if not cursor.fetchone():
                    print("Adding cloudinary fields to artifacts...")
                    cursor.execute("ALTER TABLE artifacts ADD COLUMN cloudinary_url TEXT")
                    cursor.execute("ALTER TABLE artifacts ADD COLUMN cloudinary_public_id TEXT")
                    
            connection.commit()
            print("PostgreSQL migration complete.")
            
        else:
            # SQLite migrations
            print("Applying SQLite migrations...")
            # Create users table
            connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'USER',
                    created_at TEXT NOT NULL
                )
            """)
            
            # Check if scans.user_id exists
            cursor = connection.execute("PRAGMA table_info(scans)")
            columns = [row["name"] for row in cursor.fetchall()]
            if "user_id" not in columns:
                print("Adding user_id to scans...")
                connection.execute("ALTER TABLE scans ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL")
            
            # Check if artifacts.cloudinary_url exists
            cursor = connection.execute("PRAGMA table_info(artifacts)")
            columns = [row["name"] for row in cursor.fetchall()]
            if "cloudinary_url" not in columns:
                print("Adding cloudinary fields to artifacts...")
                connection.execute("ALTER TABLE artifacts ADD COLUMN cloudinary_url TEXT")
                connection.execute("ALTER TABLE artifacts ADD COLUMN cloudinary_public_id TEXT")
                
            connection.commit()
            print("SQLite migration complete.")

if __name__ == "__main__":
    migrate_database()
