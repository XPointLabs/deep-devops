FROM node:24-bookworm-slim

WORKDIR /service

COPY tools/compat-services ./tools/compat-services
COPY tools/file-service ./tools/file-service

CMD ["node", "tools/file-service/file-service.mjs"]