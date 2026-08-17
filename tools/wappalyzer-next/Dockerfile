FROM python:3.12-slim

ARG WAPPALYZER_NEXT_VERSION=v2.0.0
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/wappalyzer-next
RUN git clone --depth 1 --branch "${WAPPALYZER_NEXT_VERSION}" \
      https://github.com/s0md3v/wappalyzer-next.git . \
    && pip install . \
    && python -m playwright install --with-deps chromium \
    && rm -rf /root/.cache/pip .git

ENTRYPOINT ["wappalyzer"]
