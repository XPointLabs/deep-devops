FROM node:24-bookworm-slim

WORKDIR /service

COPY tools/compat-services ./tools/compat-services
COPY tools/push-service ./tools/push-service

CMD ["node", "tools/push-service/push-service.mjs"]