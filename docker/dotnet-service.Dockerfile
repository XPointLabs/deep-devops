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
ENV APP_DLL=${APP_DLL}
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app .
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "dotnet \"$APP_DLL\""]

