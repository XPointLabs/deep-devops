# P01B compatibility

- Base manifest remains `survival-v2.0.1-i01b.local.json`, SHA256
  `6527338b3e5b888a22fb2cc55323259306e9f41bff69e9554706701a86dc7824`.
- The default Compose profile is unchanged.
- `docker-compose.metadata-safe.yml` is an explicit overlay.
- `DEEP_INFRA_PRIVACY_PROFILE=metadata-safe-v1` is mandatory for the strict gate.
- The default product/client/service protocol and persistence behavior are unchanged.
- The opt-in metadata-safe UAT overlay moves only the unexposed container-internal VLESS listener
  from `443` to `8443` and removes `NET_BIND_SERVICE`. A public relay requires a separate topology
  contract rather than reuse of this isolated UAT profile.
- No Docker stack was started and no network/provider call was made.
