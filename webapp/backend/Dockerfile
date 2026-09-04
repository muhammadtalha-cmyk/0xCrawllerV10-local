FROM python:3.11-slim

# Install curl (used by healthcheck) and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only requirements first for layer caching
COPY webapp/backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# The actual source code is bind-mounted at runtime via docker-compose volumes.
# We don't COPY the source here to avoid stale code in the image;
# working_dir is set to ${PWD}/webapp/backend in compose.

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
