# Fresh operator journey contract

This document defines the release-blocking first-user path for the supported LANimals appliance.

The CI journey uses an isolated HOME/XDG tree and a private network fixture created entirely inside the GitHub Actions runner. The fixture is a veth pair plus a network namespace on `192.168.250.0/30` with a known HTTP service. No public or third-party network is probed.

The release gate verifies, in order:

1. checkout-first installation creates an isolated `.venv` and working `~/.local/bin/lanimals` link;
2. explicit RFC1918 scope approval and `lanimals doctor` succeed;
3. appliance start/status/health are correct and collection does not start implicitly;
4. explicit Discovery finds the private fixture and persists its MAC-backed host record;
5. the initial identity appears as a pending baseline decision and can be explicitly accepted;
6. targeted service fingerprinting finds the fixture service and the same service is readable from durable host evidence;
7. host notes survive a read-back round trip;
8. HTML report export contains the observed host and service and is persisted in the report index;
9. a second explicit Discovery produces a comparable stable diff;
10. a trap can be explicitly deployed and is visible as active;
11. a real fixture MAC transition creates a pending `changed` baseline observation;
12. deferring the changed identity does not mutate the accepted baseline;
13. after stop/start, host/service/note/baseline/report evidence still exists while the trap is restored as non-active history;
14. the appliance stops cleanly.

The executable contract is `scripts/smoke_operator_journey.sh` and runs in CI after the unit/contract suite and the smaller lifecycle smoke test.
