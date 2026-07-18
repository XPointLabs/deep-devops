ARG NODE_IMAGE
FROM ${NODE_IMAGE}

WORKDIR /service

COPY tools/compat-services ./tools/compat-services
COPY tools/storage-service ./tools/storage-service

CMD ["node", "tools/storage-service/storage-service.mjs"]
