# syntax=docker/dockerfile:1.7
# check=skip=InvalidDefaultArgInFrom
# First-release Registry build against the exact local Protocol source. The
# production ContactResolve authority command is compiled only in this mode.
ARG SDK_IMAGE
ARG RUNTIME_IMAGE

FROM --platform=$BUILDPLATFORM ${SDK_IMAGE} AS build
ARG PROJECT
WORKDIR /src/deep-registry-api
COPY . .
COPY --from=protocol_source . /src/deep-protocol
RUN dotnet restore "$PROJECT" -p:DeepProtocolLocalCutover=true
RUN dotnet publish "$PROJECT" --configuration Release --output /app --no-restore \
    -p:DeepProtocolLocalCutover=true -warnaserror

FROM ${RUNTIME_IMAGE} AS runtime
WORKDIR /app
RUN set -eux; \
    for attempt in 1 2 3 4 5; do \
      rm -rf /var/lib/apt/lists/*; \
      apt-get update \
        -o Acquire::Retries=5 \
        -o Acquire::http::Timeout=60 \
        -o Acquire::https::Timeout=60 && break; \
      if [ "$attempt" = "5" ]; then exit 1; fi; \
      sleep $((attempt * 10)); \
    done \
    && apt-get install -y --no-install-recommends \
      -o Acquire::Retries=5 \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app .
EXPOSE 8080
ENTRYPOINT ["dotnet", "Deep.Registry.Api.dll"]
