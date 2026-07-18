# P01B data inventory

The normative inventory is `config/metadata-safe/retention-policy.v1.json`; operational explanation
is in `docs/INFRASTRUCTURE_METADATA_PRIVACY.md`.

Seven domains are covered: Xray access, Xray errors, XNode operational logs, compatibility services,
metrics, sanitized evidence and external push providers. Raw ingress IP/path, Session/mailbox/push
identifiers, capabilities and stable cross-domain correlation values are forbidden in retained Deep
logs, metric labels and evidence.

External provider retention remains unknown and is not represented as a passing local control.
