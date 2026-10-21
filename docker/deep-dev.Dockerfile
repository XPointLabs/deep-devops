# Uses Docker's bundled Dockerfile frontend; no mutable external frontend tag.
FROM --platform=$BUILDPLATFORM golang@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS nts
WORKDIR /src
COPY deep-devops/tools/nts-observer/go.mod deep-devops/tools/nts-observer/go.sum ./
RUN go mod download
COPY deep-devops/tools/nts-observer/main.go deep-devops/tools/nts-observer/main_test.go ./
RUN go test -count=1 -v ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /deep-nts-observer .

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk@sha256:ea8bde36c11b6e7eec2656d0e59101d4462f6bd630730f2c8201ed0572b295d5 AS build
ARG PROJECT
WORKDIR /src
# Keep normal NuGet feed/audit metadata inside the same locked build cache.
# This changes cache placement, not audit policy or package validation.
ENV NUGET_HTTP_CACHE_PATH=/root/.nuget/packages/.http-cache
COPY deep-protocol/ deep-protocol/
COPY xnode/ xnode/
COPY deep-registry-api/ deep-registry-api/
COPY deep-client-shared/ deep-client-shared/
COPY deep-devops/tools/deep-dev/ deep-devops/tools/deep-dev/
# Public package cache only: not a source/output/authority or credential mount.
# Sharing is locked because the three images may restore concurrently.
RUN --mount=type=cache,id=deep-dev-nuget,target=/root/.nuget/packages,sharing=locked dotnet publish "$PROJECT" -c Release -o /app -p:DeepProtocolSourceCutover=true -p:DeepProtocolLocalCutover=true

FROM build AS protocol-tests
# Executes the checked-in exact asset on the actual Linux ARM64 process. No
# native compiler or source rebuild is used by this local validation target.
RUN --mount=type=cache,id=deep-dev-nuget,target=/root/.nuget/packages,sharing=locked dotnet test deep-protocol/tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --filter 'FullyQualifiedName~DeepIdV2Root_RestoreRecreatesExactCredentialAndCommitment|FullyQualifiedName~DeepIdV2Genesis_UsesSamePhraseForAccountAndPqRoot_AndRestoresExactDid2|FullyQualifiedName~Dab2_RealNativeHybridSignaturesCloseOverExactDidAndAccount|FullyQualifiedName~Did2Verifier_RealPqGenesisClosesSignedCurrentProof|FullyQualifiedName~DeepMlDsa65NativeProviderTests|FullyQualifiedName~Did2Admission_AdvancesThresholdHeadAndRejectsChangedPrivateJournal|FullyQualifiedName~Did2Proof_EarlierLeafInSameBatchUsesFinalMapWithoutRewritingTransition'

FROM build AS mailbox-signer-tests
# Actual protected Linux custody, signatures and Unix framing; no mock can
# stand in for this lane. Not grant/authority/device activation evidence.
RUN --mount=type=cache,id=deep-dev-nuget,target=/root/.nuget/packages,sharing=locked dotnet test deep-registry-api/tests/Deep.Registry.Api.Tests/Deep.Registry.Api.Tests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:DeepProtocolLocalCutover=true --filter 'FullyQualifiedName~MailboxRoleSignerTests|FullyQualifiedName~UnixSocketEd25519ExternalSignerTests'

FROM build AS node-authority-tests
# Exercise actual Linux path/symlink/permission and protected-floor owners,
# including warm reads. This is a focused lane, not full source qualification.
RUN --mount=type=cache,id=deep-dev-nuget,target=/root/.nuget/packages,sharing=locked dotnet test xnode/tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:DeepProtocolLocalCutover=true --filter 'FullyQualifiedName~DeepIdV2NetworkPlacementRuntimeTests|FullyQualifiedName~FileDeepIdV2DirectoryProtectedHeadStoreTests|FullyQualifiedName~OperationGrammar|FullyQualifiedName~GrammarMemoBudget|FullyQualifiedName~CompleteOperationScratch'

FROM mcr.microsoft.com/dotnet/aspnet@sha256:e3736b0d423db99c6988e1ddf5ea725c14b12579bb120024e5ff7ff204a14080
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app .
COPY --from=nts /deep-nts-observer /usr/local/bin/deep-nts-observer
COPY deep-devops/docker/deep-dev-entrypoint.sh /usr/local/bin/deep-dev-entrypoint
RUN chmod 0755 /usr/local/bin/deep-dev-entrypoint
ENTRYPOINT ["/usr/local/bin/deep-dev-entrypoint"]
