# Security Policy

## Reporting a vulnerability

Do **not** disclose a suspected vulnerability publicly before it can be reviewed.

Preferred reporting path:

1. Use **Security → Report a vulnerability** for this repository when GitHub private vulnerability reporting is available.
2. Otherwise email **badbanana@proton.me** with the subject `LANimals security report`.

Include the affected commit/version, reproduction steps, expected and observed behavior, impact, and any proposed mitigation. Do not include unrelated credentials or third-party private data.

## Security-relevant scope

Reports are especially useful for issues involving:

- unsafe command or subprocess construction;
- unintended scanning beyond the operator-selected network scope;
- path traversal or unintended local file access;
- API-key exposure or unsafe VirusTotal credential handling;
- web/API behavior that permits unintended remote access;
- persistence or corruption of host/evidence history;
- dependency issues with a meaningful exploit path.

LANimals is local network-analysis software. A finding that requires intentionally exposing its local service beyond the documented operating model should identify that changed threat model explicitly.

## Supported state

Report findings against the current default branch or name the exact historical release/commit affected. Older revisions are not assumed to receive backported fixes.

## Disclosure process

I aim to acknowledge reproducible reports within seven days. Validation and remediation timing depends on severity, reproducibility, and project status; no fixed patch deadline is promised before triage is complete.

Confirmed fixes should be documented when practical. Reporter credit is welcome unless anonymity is requested.

## Good-faith research

Good-faith security research and responsible disclosure are welcome when testing is limited to systems and data the researcher owns or is explicitly authorized to assess.
