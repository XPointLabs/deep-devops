# syntax=docker/dockerfile:1.7
# check=skip=InvalidDefaultArgInFrom
# First-release local/UAT XNode build. The protocol packages and lock files are
# supplied as an explicit additional build context; there is no package fallback.
ARG SDK_IMAGE
ARG RUNTIME_IMAGE

FROM --platform=$BUILDPLATFORM ${SDK_IMAGE} AS build
ARG PROJECT
ARG TARGETARCH
ARG DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION
ARG DEEP_PROTOCOL_PACKAGE_SHA256
ARG DEEP_PROTOCOL_MEMBERSHIP_ROUTES_PACKAGE_SHA256
WORKDIR /src
COPY . .
COPY --from=protocol_cutover source-manifest.json /opt/deep-protocol/source-manifest.json
COPY --from=protocol_cutover locks/ /src/artifacts/local-protocol-cutover/locks/
COPY --from=protocol_cutover packages/Deep.Protocol.${DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION}.nupkg /opt/deep-protocol/packages/
COPY --from=protocol_cutover packages/Deep.Protocol.MembershipRoutes.${DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION}.nupkg /opt/deep-protocol/packages/
COPY --from=devops_context first-release-local.NuGet.Config /opt/deep-protocol/NuGet.Config
RUN set -eu; \
    test -n "$DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION"; \
    case "$DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION" in *[!0-9A-Za-z.+-]*) echo "invalid local protocol package version" >&2; exit 1 ;; esac; \
    test "${#DEEP_PROTOCOL_PACKAGE_SHA256}" -eq 64; \
    test "${#DEEP_PROTOCOL_MEMBERSHIP_ROUTES_PACKAGE_SHA256}" -eq 64; \
    case "$DEEP_PROTOCOL_PACKAGE_SHA256$DEEP_PROTOCOL_MEMBERSHIP_ROUTES_PACKAGE_SHA256" in *[!0-9a-f]*) echo "protocol package SHA256 values must be lowercase hexadecimal" >&2; exit 1 ;; esac; \
    printf '%s  %s\n' \
      "$DEEP_PROTOCOL_PACKAGE_SHA256" "/opt/deep-protocol/packages/Deep.Protocol.${DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION}.nupkg" \
      "$DEEP_PROTOCOL_MEMBERSHIP_ROUTES_PACKAGE_SHA256" "/opt/deep-protocol/packages/Deep.Protocol.MembershipRoutes.${DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION}.nupkg" \
      | sha256sum -c -; \
    grep -Fq "\"packageVersion\": \"${DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION}\"" /opt/deep-protocol/source-manifest.json
RUN set -eu; \
    for attempt in 1 2 3; do \
      if dotnet restore "$PROJECT" --locked-mode \
        --configfile /opt/deep-protocol/NuGet.Config \
        -p:DeepProtocolLocalCutover=true \
        -p:DeepProtocolLocalPackageVersion="$DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION" \
        > /tmp/dotnet-restore.log 2>&1; then \
        cat /tmp/dotnet-restore.log; rm -f /tmp/dotnet-restore.log; break; \
      fi; \
      cat /tmp/dotnet-restore.log >&2; \
      if ! grep -Eiq 'ResponseEnded|unexpected EOF|end of file|connection reset|connection refused|temporar(y|ily) unavailable|temporary failure|timed out|timeout|NU1301|HTTP status (408|429|500|502|503|504)' /tmp/dotnet-restore.log; then \
        rm -f /tmp/dotnet-restore.log; exit 1; \
      fi; \
      if [ "$attempt" = "3" ]; then rm -f /tmp/dotnet-restore.log; exit 1; fi; \
      rm -f /tmp/dotnet-restore.log; sleep $((attempt * 10)); \
    done
RUN case "$TARGETARCH" in \
      amd64) DOTNET_ARCH=x64 ;; \
      arm64) DOTNET_ARCH=arm64 ;; \
      *) echo "Unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && dotnet publish "$PROJECT" --configuration Release --runtime "linux-$DOTNET_ARCH" \
      --output /app --no-restore \
      -p:DeepProtocolLocalCutover=true \
      -p:DeepProtocolLocalPackageVersion="$DEEP_PROTOCOL_LOCAL_PACKAGE_VERSION"

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
    && curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 --connect-timeout 30 --max-time 300 "$XRAY_DOWNLOAD_URL" -o /tmp/xray-download/xray.zip \
    && echo "$XRAY_EXPECTED_SHA256  /tmp/xray-download/xray.zip" | sha256sum -c - \
    && unzip -q /tmp/xray-download/xray.zip -d /tmp/xray-download \
    && install -m 0755 /tmp/xray-download/xray /usr/local/bin/xray \
    && rm -rf /tmp/xray-download \
    && xray version
COPY --from=build /app .
EXPOSE 8080 8081 8082 8083 8443
ENTRYPOINT ["sh", "-c", "dotnet \"$APP_DLL\""]
