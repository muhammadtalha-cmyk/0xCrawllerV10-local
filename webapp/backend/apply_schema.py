import psycopg
import os

def run():
    conn = psycopg.connect(os.getenv('CRAWLLER_DATABASE_URL', 'postgresql://recon:reconpass@127.0.0.1:5432/recondb'))
    with open('schema_postgres.sql') as f:
        conn.execute(f.read())
    conn.commit()
    conn.close()
    print('Schema applied')

if __name__ == '__main__':
    run()
