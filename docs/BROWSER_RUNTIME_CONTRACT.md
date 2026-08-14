# Browser runtime contract

The LANimals browser is an operator surface for the local LANimals runtime. It does not independently scan a LAN and it must not claim that a mutation succeeded unless the local API accepted it.

## Acquisition boundary

The CIDR shown in the browser is an operator-approved scan boundary. Full Discovery, ARP Refresh, Host Mapping, and Rogue Detection all resolve through the runtime scope validator before collection begins.

ARP Refresh is intentionally scoped even though the host operating system may expose neighbor and interface records from several networks. Passive ARP/local-interface observations are filtered to the exact requested CIDR before they can enter the discovery cache or persistent inventory. Network addresses, broadcast addresses, malformed addresses, and observations from other subnets are not host evidence for that operation.

The terminal bridge follows the same rule. `scan arp` uses the approved default CIDR and `scan arp <CIDR>` accepts only a CIDR permitted by the runtime scope configuration. A host IP is not accepted as an ARP scan target.

## Mutation boundary

Browser POST, PATCH, and DELETE requests use the same mutation helper and include the `X-LANimals-Operator: 1` header required by the local API. A non-2xx response is an operator-visible failure, not a successful action.

This applies to baseline decisions, notes, traps, scans, risk rescoring, watchdog/anomaly actions, and other state-changing controls. In particular, note saves and trap-stop actions may display success only after the corresponding API response succeeds.

Trap bundle deployment also preserves partial-success truth. The API counts a trap as active only when its returned status is `active`, reports a separate failure count, and marks the overall result unsuccessful when any member failed. The browser displays active and failed counts separately and retains an error state for a partial deployment instead of reducing it to a clean success message.

## Page-load boundary

Opening the browser reads current local state: scope, graph, statistics, traps, baseline, reports, intelligence/events, and system information. It does not start Discovery, ARP collection, Host Mapping, Rogue Detection, service/CVE scans, traps, or other mutation operations automatically.

Periodic browser refreshes are also read-only. Active collection remains an explicit operator action.

## Evidence

The executable contracts are:

- `tests/test_browser_contract.py` — visible control/route mapping, CIDR-only ARP terminal targeting, fail-closed browser mutations, truthful trap-bundle partial failures, and read-only page initialization.
- `tests/test_observation_scope.py` — exact-CIDR passive observation filtering, scoped ARP persistence, and cold-cache Rogue MAC-change detection.
- `tests/test_api_contracts.py` — operator mutation header, scan scope rejection, same-origin terminal boundary, and API behavior.
- `tests/test_operator_lifecycle.py` — report safety, browser lifecycle invariants, and trap bundle result accounting.
- `scripts/smoke_operator_journey.sh` — real fresh-install journey against a private GitHub Actions network fixture.

The browser UI remains a local operator interface. A separately hosted static site cannot acquire live LAN evidence without a local LANimals runtime/API boundary.
