# LANimals Sites build specification

## Purpose

This is the canonical visual and interaction specification for future LANimals hosted-site builds. It does **not** override the runtime or capability contracts.

The authority order remains:

1. `capabilities.json`
2. `site_capabilities.json`
3. `docs/BROWSER_RUNTIME_CONTRACT.md`
4. this document
5. `ui/lanimals_live_map.html`

If this document appears to permit something that the first three files do not, the first three win.

The design target is a **usable LANimals operator console**, not a product landing page, portfolio showcase, security-company homepage, or fictional SOC dashboard.

## Product truth

LANimals has two different browser surfaces and they must never be visually or behaviorally conflated.

### Hosted public site

The hosted site is a `representative_workflow` surface. It has no visitor-LAN access and no connection to the LANimals local API.

It may provide a complete interactive representative session using in-memory page state. It may let the user explore topology, inventory, events, risk, baseline review, reports, traps, and terminal-style LANimals workflows. It must always remain visibly representative.

Persistent treatment required somewhere in the primary chrome:

`REPRESENTATIVE / NO LIVE LAN ACCESS`

Representative actions may mutate only the page session. They must not claim that ARP, nmap, service scanning, CVE correlation, watchdog checks, VirusTotal enrichment, traps, or any other network operation actually executed against the visitor's environment.

### Self-hosted console

The self-hosted web console is operational and talks same-origin to the local LANimals runtime, loopback-first at `http://127.0.0.1:8080`.

Every operational control must map to `site_capabilities.json`. Mutations must use the declared HTTP method and `X-LANimals-Operator: 1` when the contract requires it. No collection begins merely because the page opened.

The browser terminal is a LANimals command bridge, not an operating-system shell.

## Design intent

The site should feel like the mature browser evolution of the original LANimals CLI: direct, dense, legible, technical, and operator-owned.

Preserve the CLI DNA without simply drawing a terminal window around everything. The browser should make LANimals easier to operate while retaining the sense that every visible object corresponds to evidence, scope, state, or an explicit action.

The design should communicate:

- local-first operation
- explicit scope
- observable evidence
- operator control
- restrained security tooling aesthetics
- no hype

## Product identity

Use the exact product spelling **LANimals** everywhere.

The primary wordmark should read `LANimals` with the letters rendered in maroon. Do not use `LANIMALS`, `LAN-IMALS`, `LANimals Nexus`, or a new product name.

If the supplied badBANANA banana asset is available, use it only as a small bottom-right artifact/mark. It should feel like a quiet signature, not a mascot, hero illustration, or navigation control.

## Visual system

### Overall character

Use a dark workstation palette with maroon as the product color. The result should be quieter and more mature than generic red/black cyberpunk UI.

Recommended palette direction:

- canvas: near-black charcoal, approximately `#0b090b`
- raised surfaces: approximately `#121014` and `#18151a`
- structural borders: approximately `#2c252b`
- primary maroon: approximately `#741f2b`
- active/focus maroon: approximately `#9b3343`
- primary text: soft off-white, approximately `#ece8eb`
- secondary text: cool gray, approximately `#918a91`
- warning: restrained amber
- success: restrained green
- informational state: restrained blue

Exact values may be adjusted for accessibility. The whole interface should read as one maroon-led system rather than an old bright-red palette with a recolored logo.

Use semantic colors only where they carry meaning. Do not color every card, graph edge, or button maroon.

### Typography

Prefer a high-quality monospace or technical UI stack for operational data, commands, IPs, ports, timestamps, and labels. A restrained sans-serif may be used sparingly for longer explanatory text if it improves readability.

Use tabular numerals where possible. Preserve alignment for IP addresses, ports, risk values, timestamps, and job output.

### Texture and motion

Subtle terminal/workstation cues are appropriate: thin rules, compact status pips, faint grid structure, cursor/focus behavior, and concise state transitions.

Avoid fake CRT distortion, heavy scanlines, glitch animation, Matrix rain, pulsing neon, gratuitous grain, fake code streams, or motion that competes with evidence.

Animation should explain state changes, not decorate them.

## Information architecture

### Desktop

Prefer a four-part operator workspace:

1. **Top status bar** — `LANimals`, mode badge, approved/representative CIDR, runtime/status, concise global state.
2. **Left operation rail** — explicit acquisition and analysis actions grouped by purpose.
3. **Central topology workspace** — graph/map as the primary spatial investigation surface.
4. **Right investigation panel** — selected host, risk, identity, services, CVEs, notes, baseline status, trap/enrichment evidence, and context-specific actions.
5. **Bottom evidence/terminal drawer** — job output, event stream, report activity, and allowlisted LANimals command interaction. This drawer may collapse.

The graph should remain visually dominant without making the rest of the product feel secondary.

### Mobile

Do not shrink the desktop layout into three unusable columns.

Use:

- compact top status bar
- operation rail as a drawer or sheet
- topology as the default main view
- host investigation as a full-height or near-full-height sheet
- evidence/terminal as a separate expandable surface
- touch targets of at least 44 px where practical

The mobile experience must remain genuinely operable from a phone.

## Core operator surfaces

The visual system must account for the real operation classes already declared in `site_capabilities.json`.

### Read-only/state surfaces

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

### Explicit operator actions

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

Do not invent new operational controls merely to make the UI look more capable.

## Primary workflows

### 1. First open / empty state

Operational mode should show an intentionally empty evidence state and the approved scope. It must not fabricate hosts to make the UI attractive.

Hosted mode may load a representative scenario immediately, but the representative badge must already be visible before the scenario can be mistaken for live evidence.

### 2. Discovery-to-investigation

A primary workflow should be visually obvious:

`scope -> Discovery -> graph/inventory change -> select host -> inspect risk/evidence -> run bounded host action -> review new evidence`

The interface should preserve job progress and errors rather than replacing them with generic success toasts.

### 3. Baseline review

Pending identity changes should be clearly different from accepted baseline state. Accept and defer are explicit operator decisions and must never happen automatically.

### 4. Host investigation

Selecting a host should expose evidence before actions. Show relevant identity, hostname/vendor, current risk, risk reasons, service state, CVE state, recent events, notes, and baseline status.

Service scan, CVE scan, VirusTotal lookup, and notes should live in the host context rather than as disconnected global gimmicks.

### 5. Reports

Report creation is an explicit mutation: `POST /api/export/report` in operational mode. After creation, open or offer the read-only `/api/reports/{name}` retrieval route.

Hosted mode may generate a representative report preview only in page memory and must label it representative.

### 6. Traps

Trap deployment and stopping are explicit operator actions. Partial bundle activation must remain visibly partial. Never collapse a mixture of active and failed listeners into a clean success state.

### 7. Terminal

The terminal should look and behave like a LANimals command surface. It should expose only the allowlisted LANimals command vocabulary represented by the runtime contract. Never imply PTY access, arbitrary shell execution, or system-shell capability.

## Representative hosted dataset

Use a compact, coherent private-LAN scenario instead of random synthetic noise.

Recommended characteristics:

- one RFC1918 subnet such as `192.168.50.0/24`
- roughly 8–14 hosts, enough to make topology meaningful without becoming visual clutter
- a gateway/router, workstation, phone, printer/IoT device, media device, server/NAS, and a few ordinary clients
- at least one newly observed identity awaiting baseline review
- at least one elevated-risk host with explainable reasons
- service evidence on a subset of hosts
- one representative CVE correlation result
- one representative observation diff
- one representative trap with a small hit history
- event history that corresponds to the visible state

Use generic device names. Do not embed personal names, real home-network identifiers, real public IPs, or location-specific information.

Representative actions should update this scenario coherently. For example, a representative Service Scan may add service rows to the selected representative host and append a clearly labeled representative job/event entry.

Never label representative outcomes as live, persisted, discovered from the visitor, or uploaded from their network.

## Interaction rules

- Every click must do something meaningful or be visibly disabled with a reason.
- No dead recommendation rows.
- Do not hide failed operations behind optimistic UI.
- Preserve partial results where the backend reports partial success.
- Show the current target before network acquisition.
- Keep polling/read-only hydration separate from explicit mutation.
- Do not trigger scans or enrichment on page load or on host selection.
- A host action should remain bounded to the selected/approved target.
- Avoid confirmation dialogs for harmless read-only actions; use confirmation where accidental destructive/stateful action would materially matter.

## Keyboard and accessibility

At minimum:

- keyboard-reachable primary controls
- visible focus states
- Escape closes transient drawers/sheets where appropriate
- Enter activates focused actions
- graph selection has a non-pointer alternative through inventory/search
- semantic status is not communicated by color alone
- sufficient contrast for maroon against near-black surfaces
- motion honors reduced-motion preferences

## What not to build

Do **not** create:

- a hero section
- a marketing navbar
- pricing, testimonials, customer logos, conversion CTAs, mailing-list forms, or fake usage statistics
- a generic "Get Started" landing page before the tool
- a fake SOC command center
- unsupported AI/ML claims
- fabricated "live threats" or random alert spam
- a remote cloud scanner story
- an operating-system shell
- a neon red/green hacker theme
- glossy glassmorphism as the main visual language
- large decorative charts that do not correspond to LANimals evidence
- fake success states for disabled or representative-only functionality

Opening the site should feel like opening LANimals, not visiting the LANimals company homepage.

## Quality bar

A build is not acceptable merely because it looks polished.

It must also:

1. preserve the hosted-vs-local boundary visibly and behaviorally
2. map every operational action to `site_capabilities.json`
3. keep page-load behavior read-only
4. use explicit mutation methods for side effects
5. display scope before acquisition
6. make empty, running, partial, successful, and failed states distinct
7. make representative state impossible to confuse with local evidence
8. remain usable on a phone
9. keep `LANimals` spelling and maroon product identity consistent
10. retain the operator/CLI lineage without turning the UI into terminal cosplay
11. contain no dead controls, placeholder panels, TODO text, or invented backend promises
12. preserve the small banana signature only as a secondary artifact if the asset is supplied

## Build priority

When tradeoffs are necessary, prioritize in this order:

1. truthful capability boundary
2. usable operator workflow
3. evidence legibility
4. mobile usability
5. visual refinement
6. decorative polish

The goal is not to make LANimals look more capable than it is. The goal is to make the capabilities that already exist feel as coherent, powerful, and usable in the browser as they actually are.