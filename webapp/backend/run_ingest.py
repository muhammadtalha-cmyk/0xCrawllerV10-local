import os
from app.database import Database
from app.ingest import ingest_scan_results

def run():
    db = Database(Path('unused.db'), os.getenv('CRAWLLER_DATABASE_URL', 'postgresql://recon:reconpass@127.0.0.1:5432/recondb'))
    ingest_scan_results(db, 'f1a7d409-b2ea-4824-b36b-7976ed16613a', '/home/talha-crawller/0xCrawllerV10-local/recon_runs/thebittimes.com-20260825-162652347415+0000')
    print('Ingestion finished!')

if __name__ == '__main__':
    from pathlib import Path
    run()
