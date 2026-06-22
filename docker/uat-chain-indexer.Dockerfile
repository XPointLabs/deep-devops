# syntax=docker/dockerfile:1.6

FROM node:24-bookworm-slim

WORKDIR /service
COPY tools/uat-chain-indexer/package.json tools/uat-chain-indexer/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi
COPY tools/uat-chain-indexer/indexer.mjs ./

CMD ["node", "indexer.mjs"]
