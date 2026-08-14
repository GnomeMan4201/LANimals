# LANimals Sites handoff

This document is the handoff boundary for any hosted LANimals interface, including ChatGPT Sites builds.

The visual design may evolve aggressively. The capability claims may not.

## Source of truth

Use these files in this order:

1. `capabilities.json` — authoritative product capability/status manifest.
2. `site_capabilities.json` — browser/site action contract and hosted-vs-local behavior.
3. `docs/BROWSER_RUNTIME_CONTRACT.md` — runtime acquisition, mutation, page-load, and failure invariants.
4. `ui/lanimals_live_map.html` — current operational browser implementation.

If a proposed control cannot be mapped to an operation in `site_capabilities.json` and a capability in `capabilities.json`, it is not an operational LANimals feature yet.

## Two distinct surfaces

### Hosted site

A public hosted LANimals site is a **representative workflow surface**. It has no direct visitor-LAN access and no LANimals local API connection.

It may provide a complete, high-quality interactive walkthrough using clearly representative data: graph exploration, inventory inspection, event history, risk views, baseline decisions, investigation cards, report previews, filters, search, and terminal-style interaction.

It must visibly label the representative boundary and must not imply that Discovery, ARP, nmap, service scans, CVE correlation, watchdog, anomaly scans, VirusTotal enrichment, or honeypot deployment actually ran against the visitor's machine or LAN.

A representative action may update only page/session state. It must never be described as durable LANimals evidence.

### Self-hosted web console

The operational browser surface is served by the local LANimals runtime, loopback-first at `http://127.0.0.1:8080`.

That surface may call the routes declared in `site_capabilities.json`, subject to approved private scope, target validation, local dependencies, mutation-header requirements, and the runtime's existing failure contracts.

Starting or opening LANimals does not begin network collection. Active acquisition remains an explicit operator action.

## UI rules for future Sites builds

- Keep **LANimals** as the canonical product spelling.
- Preserve the operator-tool feel. Do not turn the project into a marketing landing page.
- A disabled live control is preferable to a fake successful control.
- Hosted mode should use an obvious status treatment such as `REPRESENTATIVE / NO LIVE LAN ACCESS`.
- Empty operational state must look intentionally empty, not be silently filled with synthetic hosts.
- Show the selected/approved CIDR or host target before a live network operation.
- A live action is successful only after the local API reports success.
- Partial success remains partial. Trap bundle active/failure counts are the reference example.
- API failure must remain visible in the operator surface; do not erase it with optimistic UI.
- The browser terminal is an allowlisted LANimals command bridge, never an OS shell.
- Legacy research scripts are not promoted to supported site controls unless their status changes in `capabilities.json`.

## Current live-operation classes

The self-hosted console currently has real implementations for:

- approved-scope Discovery, ARP Refresh, Host Map, and Rogue Detection
- approved-host service fingerprinting and CVE correlation
- persisted hosts, services, events, notes, and baseline decisions
- explainable risk rescoring
- explicit observation diff
- local system inventory
- local outbound-connection anomaly observation
- baseline availability watchdog
- local honeypot/trap state, deployment, hits, bundles, and stop controls
- local HTML report generation
- optional VirusTotal enrichment with an operator-supplied key
- derived security-audit summary
- allowlisted LANimals terminal commands

`site_capabilities.json` provides the exact route, method, target type, persistence effect, hosted behavior, and failure contract for each action.

## Known API semantic debt

Two current GET routes have operator-visible side effects and therefore must **never** be used as page-load fetches:

- `GET /api/export/report` generates and persists a report file.
- `GET /api/enrich/vt/{ip}` performs an external VirusTotal lookup and records an event.

They are explicitly recorded in `site_capabilities.json` until their HTTP semantics are tightened in a later runtime change.

## Acceptance test for a generated site

Before accepting a new LANimals site build, verify all of the following:

1. Every visible action maps to `site_capabilities.json`.
2. Hosted mode never makes or claims a live LAN acquisition.
3. Representative data is labeled before the user can mistake it for local evidence.
4. Self-hosted/live controls use only declared API routes and target types.
5. No active collection occurs on page load.
6. Mutation failure and partial success are visible.
7. No system shell is exposed.
8. Legacy/experimental modules are not shown as supported appliance capabilities.
9. The interface remains a usable operator tool rather than a promotional page.

This contract exists so the site can become visually ambitious without becoming technically fictional.
