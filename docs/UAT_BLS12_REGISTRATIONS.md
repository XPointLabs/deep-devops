# Retired UAT BLS12-381 Registrations

Last updated: 2026-07-18.

All private material corresponding to the public registrations below was
previously tracked and is compromised. These values are retained only to
identify registrations that Mr. X must exit/revoke. They are not prepared or
active configuration and must never be reused.

UAT router nodes now use the same Ed25519 public key for:

- signed relay contact `routerId`;
- staking registration `serviceNodePubkey`;
- registry `nodeId` / `ed25519PublicKey`.

The old temporary `0201` / `0202` / `0203` contract service-node pubkeys are
still present on-chain as contract IDs 1, 2, and 3, but they are in
`exit-requested` state. Contract IDs 4, 5, and 6 use the retired Ed25519
service-node pubkeys below.

Operator and rewards wallet:

```text
0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0
```

After rotation, query the new live registration payloads:

```powershell
Invoke-RestMethod http://192.168.1.44:28082/registrations/0xb0cE3b1229c00d1B85c7083E31Dae531f3B352C0
```

The new live payload must include the rotated BLS12-381 public key and
proof-of-possession signature for the configured `ServiceNodeRewards` contract
and the Ed25519 service-node pubkey below.

## Router Node 1

```text
nodeId / ed25519 / serviceNodePubkey: 5979c8dda9c10cff26db46b96cefd9ea3527c2ce90b99886342d71c54e8ed4dc
activeContractId: 4
blsPublicKey: 000000000000000000000000000000001938ef58d7d90f098abec7169bbf1a2eee25a26670ea811d35621872b816507a22e5176f67771f8544ab877e2b47d9af00000000000000000000000000000000152d48b5e8d871f41d5ee0219cac7bd44abb65f8429077eabe5dd82aed24ceee4822ac39151e9815b4d32168d79d1e16
transport: vless://192.168.1.44:20443
```

## Router Node 2

```text
nodeId / ed25519 / serviceNodePubkey: 298f4fb1eb601d5f900332c728829d19be6282f5e50c2bd3cea055a27d83c51c
activeContractId: 5
blsPublicKey: 000000000000000000000000000000000cf99b87401af125be8b7799d74c1ecb63d63f1467e60c6b305e4570cbfe2f6c1e837bbf183bab2560337686393cb91d00000000000000000000000000000000177cbbea5d36e749da422db5938a43b8ef1ae9a372e68dc0fe540ee80f1d100dfad5e3b072a76836064e4f22b52f1f34
transport: vless://192.168.1.44:20444
```

## Router Node 3

```text
nodeId / ed25519 / serviceNodePubkey: c08f5aecc314da789193719a15f1fa2e21a1aeadf266a6b53bd667974870c846
activeContractId: 6
blsPublicKey: 00000000000000000000000000000000081e12a9393dc33a4839b5b3ac7351ba01029cc972eb0f812acbe65abc8f85e01cb504888c0c2a454cdb7f237db2b5bf000000000000000000000000000000000f1dac4748a7c5b5ec8d43a1f8be2a827d067c0504da79667d0e79bab2ac79ae8462534049fd12f64cc153c087cac4d6
transport: vless://192.168.1.44:20445
```
