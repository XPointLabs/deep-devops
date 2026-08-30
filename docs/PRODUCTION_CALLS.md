# Production Calls

This document describes the currently implemented call components. The public
release target additionally requires transport-neutral E2EE signaling and the
signed media-carrier policy from `../../docs/architecture/THREAT-MODEL.md`.

Deep call setup is split into three production components:

- `deep-registry-api` stores short-lived, end-to-end encrypted signaling envelopes and authenticates every sender and inbox request with the account Ed25519 key.
- `turn-service` provides STUN/TURN traversal. It receives only DTLS-SRTP encrypted media packets and cannot decrypt call media.
- the MAUI client creates the WebRTC peer connection and obtains one-hour coturn REST credentials through a signed `/api/calls/ice-servers/{sessionId}` request.

The previous standalone Node `calls-service` is not part of production.

## Server prerequisites

The registry host must already have the valid Certbot certificate for `registry.xpoint.network`. Generate the shared TURN secret once and keep it outside Git:

```bash
sudo install -d -m 700 /opt/xpoint-prod/deep-devops/secrets
openssl rand -base64 48 | sudo tee /opt/xpoint-prod/deep-devops/secrets/turn-shared-secret >/dev/null
sudo chmod 600 /opt/xpoint-prod/deep-devops/secrets/turn-shared-secret
```

Open the TURN listeners and the deliberately narrow relay range:

```bash
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
sudo ufw allow 5349/udp
sudo ufw allow 49160:49200/tcp
sudo ufw allow 49160:49200/udp
```

## Deploy

From `/opt/xpoint-prod/deep-devops`:

```bash
docker compose --env-file .env.production \
  -f docker-compose.staking.prod.local.yml up -d --build registry

docker compose -f docker-compose.client-services.prod.yml \
  --env-file .env.production \
  up -d turn-service
```

Set `DEEP_TURN_PUBLIC_HOST` to the exact DNS name on the coturn certificate and,
when automatic public-IP discovery is unsuitable, set `DEEP_TURN_EXTERNAL_IP` to
the origin address. The startup boundary validates those values and secret/cert
files, creates a mode-`0600` runtime config on `tmpfs`, and starts coturn with only
the config path in argv.

Nginx must route `/api/calls` on `registry.xpoint.network` to the registry API (`http://127.0.0.1:28180`), not to port `19103`.

`registry.xpoint.network` is currently proxied by Cloudflare, which does not forward standard TURN ports. A DNS-only `turn.xpoint.network` record and TURN/TLS improve compatibility with restricted networks but do **not** constitute censorship resistance: the domain and origin IP remain enumerable and blockable. Production v1 obtains short-lived relay descriptors from the signed rotating media bridge catalog and provides at least one independently hosted TLS/HTTPS-compatible fallback. ICE configuration is fetched at runtime, so endpoint rotation does not require a new client build.

## Verify

An unsigned credential request must be rejected:

```bash
curl -i https://registry.xpoint.network/api/calls/ice-servers/05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Expected status: `401 Unauthorized`. This verifies only the legacy pre-clean-break
call stack. The first public clean-break release does not enable direct ICE and
does not use this Registry inbox as steady-state signaling. Its acceptance gate
uses E2EE message-plane signaling, relay-only ICE, rotating masked relay
descriptors and UDP-blocked TCP fallback as specified in
`../../docs/architecture/V1-RELEASE-SCOPE.md`.

After Certbot renews the certificate, restart coturn so it opens the renewed key material:

```bash
docker compose -f /opt/xpoint-prod/deep-devops/docker-compose.client-services.prod.yml restart turn-service
```
