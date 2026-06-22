FROM node:24-bookworm-slim

WORKDIR /contracts
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
EXPOSE 8545

