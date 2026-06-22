# syntax=docker/dockerfile:1.6

FROM node:24-bookworm-slim

WORKDIR /service
COPY tools/uat-reward-keeper/package.json tools/uat-reward-keeper/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi
COPY tools/uat-reward-keeper/keeper.mjs ./

CMD ["node", "keeper.mjs"]
