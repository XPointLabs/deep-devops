# P01B security self-assessment

Decision: implementation is suitable for independent review; production readiness remains false.

Controls:

- Xray access sink absent and warning/error visibility retained.
- XNode request-noise categories raised to Warning.
- Per-service Docker local logs are size-bounded.
- Fresh local wall-clock observation binds the exact archive set and rejects files older than 24
  hours, stale observation clocks and future archive mtimes.
- Metric label allowlist blocks identifier and network/path labels.
- Evidence scanner requires exact positive input counts, structurally parses JSON/JSONL and reports
  no matched values, logical paths or filenames.
- Exact merged-Compose validation rejects host namespace sharing, public/additional listeners,
  Docker socket/bind mounts, devices, privilege, added capabilities, weakened security options and
  unexpected services/networks/volumes/secrets/build keys.
- Strict gate binds P01 expectations and pinned clean XNode source.
- Break-glass closure, deletion verification and key-reference separation are machine checked.

Residual risks:

- bounded Docker logs are not proof of wall-clock deletion; a local receipt is only a point-in-time
  observation and not proof of continuous enforcement or prior deletion;
- host/runtime administrators can access live traffic and memory;
- global timing, size, IP and radio metadata remain;
- provider retention and deletion are not locally provable;
- static Compose/Xray checks are not live runtime evidence.

Independent privacy/SRE review is required. This document is not self-approval.
