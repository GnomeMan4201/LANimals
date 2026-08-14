# LANimals Sites build prompt

Use this prompt when generating or rebuilding the LANimals hosted site from the repository source.

---

Build the LANimals site as a **usable operator tool**, not a marketing site.

Before designing anything, read and obey these repository files in this order:

1. `capabilities.json`
2. `site_capabilities.json`
3. `docs/BROWSER_RUNTIME_CONTRACT.md`
4. `docs/SITES_BUILD_SPEC.md`
5. `docs/SITES_HANDOFF.md`
6. `ui/lanimals_live_map.html`

The first three files are the hard capability boundary. If a visual idea conflicts with them, the capability contract wins.

## Core product requirement

The hosted public site is a **representative workflow surface**. It does not have direct access to the visitor's LAN and it does not connect to the local LANimals API.

The hosted experience can be deeply interactive, but it must persistently and visibly identify itself as:

`REPRESENTATIVE / NO LIVE LAN ACCESS`

Never claim that the hosted site actually scanned the visitor's network, performed ARP/nmap discovery, fingerprinted services, correlated live CVEs, ran watchdog/anomaly checks, queried VirusTotal, deployed honeypots, or persisted LANimals evidence.

Representative actions may mutate only in-memory page/session state and must remain clearly representative.

The real self-hosted LANimals browser console is operational against the local runtime. Every operational control must map exactly to `site_capabilities.json`, including method, route, target, persistence, operator-header requirement, and failure semantics. Do not invent a new live feature because it looks useful.

## Design direction

Make this feel like the browser-native evolution of the original LANimals CLI: technical, compact, direct, evidence-first, and operator-controlled.

Do not recreate the old CLI screenshot literally. Translate its character into a much more usable site.

Use exact product spelling: **LANimals**.

Render the `LANimals` wordmark in maroon. Carry a mature maroon-led palette through the full interface rather than keeping a bright-red cyberpunk palette with a recolored logo.

Use a dark charcoal workstation foundation, restrained borders, soft off-white text, cool muted labels, maroon for product identity/focus/primary operator emphasis, and restrained semantic amber/green/blue only where they communicate real state.

Avoid neon hacker clichés, Matrix styling, fake code rain, aggressive scanlines, heavy glow, fake SOC visuals, generic glassmorphism, or decorative charts with no evidence meaning.

If the supplied badBANANA banana asset is present, place it as a small bottom-right artifact/signature. Keep it subtle. It is not the hero, mascot, or navigation.

## Layout

On desktop, build a real operator workspace:

- top status bar with `LANimals`, hosted/live mode, scope, and runtime/status
- left operation rail for acquisition and analysis actions
- central topology/graph workspace as the main investigation surface
- right host investigation panel for selected-host evidence and bounded actions
- collapsible bottom evidence/terminal drawer for job output, events, reports, and LANimals command interaction

On mobile, do not squeeze three desktop columns into a narrow screen. Use the topology as the default main surface, operation controls in a drawer/sheet, host investigation as a full or near-full height sheet, and terminal/evidence as a separate expandable surface. Make it genuinely usable from a phone.

## Controls that must be represented correctly

Account for the real LANimals operation classes already declared by the repo:

Read/state surfaces:
- runtime health
- approved scope
- network graph
- host inventory
- event feed
- baseline review queue
- observation diff
- trap inventory
- security audit summary
- persisted report history/retrieval

Explicit operator actions:
- Discovery
- ARP Refresh
- Host Map
- Rogue / identity-change detection
- Service fingerprinting
- CVE correlation
- System inventory
- Outbound connection anomaly scan
- Baseline availability watchdog
- Risk rescore
- Baseline accept/defer
- Host note save
- Trap deploy
- Trap bundle deploy
- Trap stop
- VirusTotal IP enrichment
- HTML operator report generation
- allowlisted LANimals terminal commands

Do not add operational-looking controls beyond the machine contract.

## Hosted representative scenario

Use one coherent RFC1918 representative LAN, for example `192.168.50.0/24`, with roughly 8–14 generic hosts. Include enough state to exercise LANimals meaningfully without visual clutter:

- gateway/router
- workstation
- phone
- printer or IoT device
- media device
- NAS/server
- several ordinary clients
- one pending baseline identity change
- one elevated-risk host with explainable reasons
- services on a subset of hosts
- one representative CVE result
- one observation diff
- one representative trap with a small hit history
- event history that actually matches what the interface shows

Use generic names only. Do not include personal names, real home identifiers, location-specific data, real public IPs, or fake personal telemetry.

When the user runs a representative action, update the representative scenario coherently. For example, a representative Service Scan can add service rows to the selected representative host and append a `REPRESENTATIVE` job/event entry. Never describe that result as live, discovered from the visitor, or persisted evidence.

## Interaction requirements

Every visible control must either work meaningfully or be clearly disabled with a reason. No dead recommendations, inert rows presented as actions, placeholder buttons, fake loading loops, or TODO panels.

No network acquisition, enrichment, report generation, trap deployment, baseline mutation, or other side effect may occur on page load.

Read-only hydration/polling must remain separate from explicit mutations.

Operational mutation calls must use the declared method and the `X-LANimals-Operator: 1` boundary where required.

Report generation is an explicit `POST /api/export/report`; after creation use the returned read-only `/api/reports/{name}` route.

VirusTotal enrichment is an explicit `POST /api/enrich/vt/{ip}` and is never a page-load or host-selection fetch.

Partial success must remain visibly partial. Backend errors must remain visible. Do not convert them into optimistic success UI.

Show the target scope/host before an acquisition action executes.

Baseline accept/defer must remain explicit operator decisions.

The terminal is an allowlisted LANimals command bridge only. Never imply arbitrary shell or PTY access.

## CLI lineage

Use the old CLI feel as interaction language, not as decoration.

Good ways to preserve it:

- compact aligned status output
- monospace operational data
- job/evidence lines that read like real tool output
- concise command vocabulary
- exact IP/port/timestamp alignment
- command history and selected-host context
- restrained state pips and thin separators

Do not wrap the whole application in a fake terminal frame.

## Accessibility and quality

Provide visible keyboard focus, keyboard-reachable primary actions, a non-pointer alternative to graph selection through inventory/search, semantic state beyond color alone, reduced-motion support, and touch targets appropriate for mobile.

Use high contrast with the maroon palette.

Build complete empty, running, success, partial, and failure states.

## Explicitly forbidden

Do not create:

- hero marketing section
- product-marketing navbar
- testimonials
- pricing
- customer logos
- conversion CTAs
- newsletter forms
- fake usage numbers
- generic `Get Started` landing page before the tool
- invented live threat counts
- fictional AI/ML detection claims
- fake cloud scanning
- fake remote LAN access
- operating-system shell
- random alert spam
- decorative panels that do not correspond to LANimals state

Opening the site should feel like opening LANimals itself.

## Final acceptance gate

Before considering the build finished, self-check all of the following:

1. Every operational control maps to `site_capabilities.json`.
2. Hosted mode is impossible to mistake for live LAN access.
3. Representative data is labeled before it can be mistaken for evidence.
4. No active collection or side effect occurs on page load.
5. Scope is visible before acquisition.
6. Mutation failures and partial results remain visible.
7. The terminal never implies a system shell.
8. `LANimals` capitalization is correct everywhere.
9. The maroon visual system is applied consistently throughout the tool.
10. The design retains the old CLI/operator lineage without becoming terminal cosplay.
11. Desktop and phone workflows are both genuinely usable.
12. There are no dead controls, placeholders, TODOs, or backend promises not present in the repo.
13. The banana asset, if supplied, is only a small bottom-right signature.
14. The result is an operator interface, not a marketing campaign.

Do not return a design brief or describe what you would build. Build the actual working site experience to the highest quality possible within these constraints.

---
