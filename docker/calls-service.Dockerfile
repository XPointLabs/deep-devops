FROM node:24-bookworm-slim

WORKDIR /service

COPY tools/calls-service ./tools/calls-service

CMD ["node", "tools/calls-service/calls-service.mjs"]
