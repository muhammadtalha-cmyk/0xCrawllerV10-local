FROM node:22-alpine
ARG RETIREJS_VERSION=5.4.3
RUN npm install -g "retire@${RETIREJS_VERSION}" \
    && npm cache clean --force
WORKDIR /workspace
ENTRYPOINT ["retire"]
CMD ["--help"]
