import os
from sqlalchemy import create_engine

DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://recon:reconpass@localhost:5432/recondb'
)

engine = create_engine(DATABASE_URL)
