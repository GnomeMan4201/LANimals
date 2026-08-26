# THREATMAP handoff v1

LANimals can export one observed record to the private THREATMAP FIELD service without receiving direct database access.

The integration lives in `core/threatmap_handoff.py` and is intentionally narrow:

1. LANimals canonicalizes the source observation and computes SHA-256.
2. LANimals builds a schema-v1 evidence candidate containing the source record and its hash.
3. LANimals sends `handoff.lanimals.accept` to the owner-only local `threatmapd` Unix socket.
4. THREATMAP recalculates the source hash before accepting anything.
5. THREATMAP assigns deterministic evidence identity and writes immutable evidence through its own domain store.

LANimals does not create THREATMAP entities, relationships, or attribution through this handoff.

## Shared canonical test vector

Canonical JSON:

```json
{"host":"192.0.2.44","port":22,"scope":"192.0.2.0/24","service":"ssh"}
```

SHA-256:

```text
5c42d90124f84707773c59961429766c789d1f57b55173b447261dd16a28cf18
```

This vector is regression-tested so canonical drift breaks CI rather than silently changing provenance hashes.

## Local socket checks

Before connecting, LANimals requires the configured path to be:

- a direct Unix socket, not a symlink;
- owned by the current user;
- no broader than mode `0600`.

`threatmapd` performs its own peer-UID validation independently.

This module does not scan, broaden network scope, or bypass LANimals' existing approved-scope controls. It only transports an observation that already exists.
