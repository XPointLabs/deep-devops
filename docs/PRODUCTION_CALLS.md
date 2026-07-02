# Production Calls

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
  up -d turn-service
```

Nginx must route `/api/calls` on `registry.xpoint.network` to the registry API (`http://127.0.0.1:28180`), not to port `19103`.

`registry.xpoint.network` is currently proxied by Cloudflare, which does not forward standard TURN ports. The production default therefore publishes the origin IP through `DEEP_TURN_PUBLIC_HOST`. To enable censorship-resistant TURN over TLS, create a DNS-only `turn.xpoint.network` record to the same origin, issue a certificate for it, set `DEEP_TURN_PUBLIC_HOST=turn.xpoint.network`, and add `turns:turn.xpoint.network:5349?transport=tcp` to `Calls__IceUrls`. ICE configuration is fetched at runtime, so this change does not require a new client build.

## Verify

An unsigned credential request must be rejected:

```bash
curl -i https://registry.xpoint.network/api/calls/ice-servers/05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Expected status: `401 Unauthorized`. Verify TURN from another host with coturn utilities and a credential issued by the signed client endpoint. Also verify both direct ICE and forced relay calls before a client release.

After Certbot renews the certificate, restart coturn so it opens the renewed key material:

```bash
docker compose -f /opt/xpoint-prod/deep-devops/docker-compose.client-services.prod.yml restart turn-service
```
