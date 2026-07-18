ARG NODE_IMAGE
FROM ${NODE_IMAGE}

WORKDIR /service

COPY tools/compat-services ./tools/compat-services
COPY tools/push-service ./tools/push-service

CMD ["node", "tools/push-service/push-service.mjs"]
