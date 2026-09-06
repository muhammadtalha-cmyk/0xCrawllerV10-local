FROM ruby:3.3-slim

ARG WHATWEB_VERSION=v0.6.4
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git build-essential libyaml-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${WHATWEB_VERSION}" https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && cd /opt/whatweb \
    && bundle config set --local without 'test development mongo rchardet' \
    && bundle install \
    && chmod +x /opt/whatweb/whatweb
WORKDIR /opt/whatweb
ENTRYPOINT ["ruby", "/opt/whatweb/whatweb"]
CMD ["--help"]
