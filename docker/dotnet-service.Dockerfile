# check=skip=InvalidDefaultArgInFrom
# Keep full-image references mandatory and provided via pinned compose/runtime inputs.
ARG SDK_IMAGE
ARG RUNTIME_IMAGE

FROM ${SDK_IMAGE} AS build
ARG PROJECT
WORKDIR /src
COPY . .
RUN dotnet restore "$PROJECT"
RUN dotnet publish "$PROJECT" --configuration Release --output /app --no-restore

FROM ${RUNTIME_IMAGE} AS runtime
ARG APP_DLL
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
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app .
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "dotnet \"$APP_DLL\""]

