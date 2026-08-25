# Archived UAT Client Handoff

Archived: 2026-08-26.

This snapshot described the retired June 2026 cleartext UAT client lane. Its
repository paths, commit claims, APK locations, LAN endpoints, device record,
and verification results are no longer authoritative and must not be used to
build, sign, install, or approve a client.

The supported local and physical client workflow is documented in
`docs/SURVIVAL_DEV_MAUI_MAILBOX_GRANTS.md`, `docs/SURVIVAL_UAT_TLS.md`, and
`docs/SURVIVAL_DEV_STACK.md`. Current clients consume authenticated HTTPS
privacy routes and independent X25519 agreement keys; they do not use direct
cleartext XNode client endpoints.

The historical body was intentionally removed so stale paths, pushed-commit
claims, and obsolete endpoint examples cannot be mistaken for a current
handoff.
