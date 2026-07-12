# Storage Service Limits

`storage-service` is public-facing. Its defaults are intentionally finite and can be overridden with `DEEP_STORAGE_*` compose variables or the matching `STORAGE_*` process variables.

| Setting | Default | Purpose |
| --- | ---: | --- |
| `STORAGE_MAX_REQUEST_BYTES` | 262144 | Rejects a request before its full body is buffered. |
| `STORAGE_MAX_MESSAGE_BYTES` | 65536 | Maximum decoded message data. |
| `STORAGE_MAX_MESSAGES_PER_ACCOUNT` | 10000 | Maximum retained messages for one `pubkey`. |
| `STORAGE_MAX_BYTES_PER_ACCOUNT` | 268435456 | Maximum retained decoded bytes for one `pubkey`. |
| `STORAGE_MAX_MESSAGES` | 100000 | Global message count ceiling. |
| `STORAGE_MAX_BYTES` | 2147483648 | Global decoded-data ceiling. |
| `STORAGE_RETRIEVE_PAGE_SIZE` | 100 | Maximum messages returned by one retrieve request. |
| `STORAGE_MAX_RETRIEVE_PAGE_BYTES` | 1048576 | Maximum serialized retrieve page size. |
| `STORAGE_MAX_MUTATION_HASHES` | 1000 | Maximum hashes accepted by multi-message mutations. |
| `STORAGE_MAX_PIPELINE_REQUESTS` | 20 | Maximum sequence or batch items. |
| `STORAGE_RATE_LIMIT_PER_MINUTE` | 600 | Per-source-IP fixed-window storage API limit, with no queue. |
| `STORAGE_RATE_LIMIT_MAX_CLIENTS` | 10000 | Bounded in-memory source-IP tracking. |
| `STORAGE_SNAPSHOT_EVERY_MUTATIONS` | 100 | Journal events between atomic snapshots. |

Retrieve accepts optional `limit` and returns `more` when a continuation is available. Continue with the last returned message's `hash` in `last_hash`.

Persistence keeps an append-only `storage.journal.ndjson` next to `storage.json`. The snapshot format is versioned and legacy array snapshots continue to load. Backups, restores, and volume migrations must retain both files. Snapshot replacement is atomic; journal replay is idempotent, so a restart during compaction recovers the latest durable state.
