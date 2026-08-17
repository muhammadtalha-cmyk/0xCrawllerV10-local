# Recon Database Layer

This module adds PostgreSQL asset intelligence storage.

Start database:

```
docker compose -f database/docker-compose.yml up -d
```

Apply schema:

```
psql -h localhost -U recon -d recondb -f database/schema.sql
```

The database stores normalized recon intelligence:

- scan runs
- assets
- DNS records
- ports/services
- technologies and versions
- endpoints
- screenshots
- evidence
- future vulnerability findings

The next integration step is adding ingestion adapters that read existing pipeline JSON outputs and populate these tables.
