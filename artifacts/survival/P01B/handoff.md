# P01B handoff

Owner: Mr. X

Reviewer checklist:

1. Confirm the default Compose profile is unchanged.
2. Render base plus `docker-compose.metadata-safe.yml`; verify seven services, exact profile label,
   exact internal network/loopback ports/named volumes/node secrets, no added capabilities, bounded
   logging, exact label maps/healthchecks/depends_on and Warning-level router categories.
3. Run `node --test scripts/metadata-privacy-gate.test.mjs`.
4. Confirm seeded ingress IP/path/Session/mailbox/push/correlation and metric-label cases fail.
5. Run the strict gate with exact positive artifact and metric counts. Verify empty, unsupported,
   binary, malformed JSON/JSONL and count-mismatched selections exit `2`.
6. Verify a seeded leak exits `1` and the complete console/summary serialization contains neither
   raw values nor logical paths/filenames.
7. Mutate host network/PID/IPC, public ports, Docker socket/bind mounts, devices, privilege,
   capabilities, security options, host-gateway, services/networks/listeners/volumes/secrets,
   Xray access/log level, profile, metric labels, key references and break-glass booleans; each
   must fail.
8. Verify a local wall-clock receipt against its exact archive root and then seed an expired mtime;
   the expired archive must fail. Also reject empty/substituted roots, path/content swaps, count
   drift, stale/future clocks and extra receipt claims. Confirm the default status is `not-run`.
9. Confirm no Docker up, provider call or product runtime change is claimed.
