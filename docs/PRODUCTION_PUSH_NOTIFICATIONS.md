# Production push notifications

Deep uses `push.xpoint.network` as the public subscription endpoint. The production service stores subscriptions and its durable retry queue in PostgreSQL and sends encrypted data-only notifications through Firebase Cloud Messaging.

## Secrets

Create the following root-owned files on the production host. Never add them to Git:

```bash
sudo install -d -m 700 /opt/xpoint-prod/deep-devops/secrets
openssl rand -base64 48 | sudo tee /opt/xpoint-prod/deep-devops/secrets/push-db-password >/dev/null
openssl rand -base64 48 | sudo tee /opt/xpoint-prod/deep-devops/secrets/push-internal-token >/dev/null
sudo install -m 600 firebase-service-account.json /opt/xpoint-prod/deep-devops/secrets/firebase-service-account.json
sudo chmod 444 /opt/xpoint-prod/deep-devops/secrets/*
```

The directory remains root-only (`0700`). Files are read-only because non-root containers receive Compose file secrets as bind mounts and must be able to read them; they are not traversable by other host users through the protected directory.

The Firebase service account must belong to the same Firebase project as the Android `google-services.json` for package `network.xpoint.deep`.

## Start or update

Load or build the push image as `xpoint/deep-push-notification-server:prod`, then run:

```bash
cd /opt/xpoint-prod/deep-devops
docker compose -f docker-compose.client-services.prod.yml up -d push-db push-service storage-service
docker compose -f docker-compose.client-services.prod.yml ps
curl -fsS http://127.0.0.1:19102/health/ready
```

Expose only `/subscribe`, `/unsubscribe`, and the health endpoints through Nginx. `/_compat/push-notify` accepts authenticated requests, but external storage nodes need to reach it; authentication is mandatory even when Nginx permits the route.

An Nginx virtual host is provided at `nginx/push.xpoint.network.conf`. Install it in `/etc/nginx/sites-available`, enable its symlink in `sites-enabled`, and include `push.xpoint.network` when obtaining or expanding the Certbot certificate.

The co-located storage service uses `push-internal-token`. Operator storage nodes sign each notification with their existing Ed25519 node key. The push server resolves that key through `https://registry.xpoint.network/api/nodes` and only accepts active nodes with timestamps within five minutes.

## Diagnostics

```bash
curl -fsS https://push.xpoint.network/health/live
curl -fsS https://push.xpoint.network/health/ready
docker compose -f docker-compose.client-services.prod.yml logs --tail 200 push-service push-db
docker compose -f docker-compose.client-services.prod.yml exec push-db \
  psql -U deep_push -d deep_push -c 'select "Status", count(*) from "Deliveries" group by "Status";'
```

Provider tokens, notification encryption keys, message bodies, and Firebase credentials must never be written to logs.
