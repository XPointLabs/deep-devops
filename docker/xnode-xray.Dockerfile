ARG SDK_IMAGE
ARG RUNTIME_IMAGE

FROM --platform=$BUILDPLATFORM ${SDK_IMAGE} AS build
ARG PROJECT
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN dotnet restore "$PROJECT" --locked-mode
RUN case "$TARGETARCH" in \
      amd64) DOTNET_ARCH=x64 ;; \
      arm64) DOTNET_ARCH=arm64 ;; \
      *) echo "Unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && dotnet publish "$PROJECT" --configuration Release --runtime "linux-$DOTNET_ARCH" --output /app --no-restore

FROM ${RUNTIME_IMAGE} AS runtime
ARG APP_DLL
ARG TARGETARCH
ARG XRAY_VERSION
ARG XRAY_SHA256
ARG XRAY_SHA256_AMD64
ARG XRAY_SHA256_ARM64
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
    && test -n "$XRAY_VERSION" \
    && case "${TARGETARCH:-amd64}" in \
      amd64) XRAY_ASSET="Xray-linux-64.zip"; XRAY_EXPECTED_SHA256="${XRAY_SHA256_AMD64:-$XRAY_SHA256}" ;; \
      arm64) XRAY_ASSET="Xray-linux-arm64-v8a.zip"; XRAY_EXPECTED_SHA256="${XRAY_SHA256_ARM64:-$XRAY_SHA256}" ;; \
      *) echo "Unsupported TARGETARCH for Xray download: ${TARGETARCH:-}" >&2; exit 1 ;; \
    esac \
    && test "${#XRAY_EXPECTED_SHA256}" -eq 64 \
    && case "$XRAY_EXPECTED_SHA256" in *[!0-9a-f]*) echo "selected Xray SHA256 must be 64 lowercase hexadecimal characters" >&2; exit 1 ;; esac \
    && XRAY_DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$XRAY_ASSET" \
    && curl -fsSL "$XRAY_DOWNLOAD_URL" -o /tmp/xray-download/xray.zip \
    && echo "$XRAY_EXPECTED_SHA256  /tmp/xray-download/xray.zip" | sha256sum -c - \
    && unzip -q /tmp/xray-download/xray.zip -d /tmp/xray-download \
    && install -m 0755 /tmp/xray-download/xray /usr/local/bin/xray \
    && rm -rf /tmp/xray-download \
    && xray version
COPY --from=build /app .
EXPOSE 8080 8081 443
ENTRYPOINT ["sh", "-c", "dotnet \"$APP_DLL\""]
