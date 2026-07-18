ARG NODE_IMAGE
FROM ${NODE_IMAGE}

WORKDIR /service

COPY tools/calls-service ./tools/calls-service

CMD ["node", "tools/calls-service/calls-service.mjs"]
