ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0

FROM ${SDK_IMAGE} AS build
ARG PROJECT
WORKDIR /src
COPY . .
RUN dotnet restore "$PROJECT"
RUN dotnet publish "$PROJECT" --configuration Release --output /app --no-restore

FROM ${RUNTIME_IMAGE} AS runtime
ARG APP_DLL
ARG TARGETARCH
ARG XRAY_VERSION=v26.3.27
ARG XRAY_DOWNLOAD_URL
ARG XRAY_SHA256
ENV APP_DLL=${APP_DLL}
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
      curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp/xray-download \
    && if [ -z "${XRAY_DOWNLOAD_URL:-}" ]; then \
        case "${TARGETARCH:-amd64}" in \
          amd64) XRAY_ASSET="Xray-linux-64.zip" ;; \
          arm64) XRAY_ASSET="Xray-linux-arm64-v8a.zip" ;; \
          *) echo "Unsupported TARGETARCH for Xray download: ${TARGETARCH:-}" >&2; exit 1 ;; \
        esac; \
        XRAY_DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$XRAY_ASSET"; \
    fi \
    && curl -fsSL "$XRAY_DOWNLOAD_URL" -o /tmp/xray-download/xray.zip \
    && if [ -n "${XRAY_SHA256:-}" ]; then echo "$XRAY_SHA256  /tmp/xray-download/xray.zip" | sha256sum -c -; fi \
    && unzip -q /tmp/xray-download/xray.zip -d /tmp/xray-download \
    && install -m 0755 /tmp/xray-download/xray /usr/local/bin/xray \
    && rm -rf /tmp/xray-download \
    && xray version
COPY --from=build /app .
EXPOSE 8080 8081 443
ENTRYPOINT ["sh", "-c", "dotnet \"$APP_DLL\""]
