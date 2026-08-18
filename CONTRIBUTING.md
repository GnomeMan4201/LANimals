# Contributing to LANimals

LANimals is a local-first network intelligence appliance with explicit scope and evidence contracts. Contributions are welcome when they improve correctness, safety, reproducibility, usability, documentation, or the fidelity of the supported capability surface.

The supported product is the **v2.1 self-hosted appliance**. Historical research modules remain `experimental_legacy` unless they are brought behind the same scope, persistence, error-handling, and automated-test contracts as the supported operator path.

## Good contribution targets

Useful contributions include:

- regression tests for observed bugs;
- scope-validation and fail-closed boundary tests;
- API/UI/CLI consistency fixes;
- capability-contract corrections where `capabilities.json` and runtime behavior drift;
- fresh-install and smoke-test improvements;
- accessibility and operator-workflow improvements;
- documentation corrections tied to observed behavior;
- evidence-store, migration, or export correctness fixes;
- carefully scoped work that graduates an `experimental_legacy` module into a supported state with complete contract coverage.

Do not promote a capability by changing documentation alone. If behavior is not implemented and validated, `capabilities.json` must not claim that it is supported.

## Safety and authorization

Only test collection or scanning behavior on networks you own or are explicitly authorized to assess.

Do not include the following in public issues or pull requests:

- private host inventories;
- MAC addresses or internal hostnames from real environments;
- API keys or credentials;
- unredacted local evidence databases;
- sensitive reports from networks you do not intend to publish.

Use synthetic or sanitized data whenever a reproducible example is needed.

Security-sensitive findings should follow [`SECURITY.md`](SECURITY.md) rather than being disclosed in a public issue.

## Development setup

The tested path is Linux, with Pop!_OS / Ubuntu as the primary reference environment.

System requirements:

```bash
sudo apt install python3-venv nmap iproute2
```

From a fresh checkout:

```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
./install.sh
```

LANimals is intentionally checkout-first. Do not assume `pip install .` is a supported deployment path.

## Validation before a pull request

Run the repository's supported validation path:

```bash
pytest tests/ -v --tb=short
bash scripts/smoke_appliance.sh
```

If your environment has `pre-commit` installed, also run:

```bash
pre-commit run --all-files
```

For changes touching scope, API mutation, command dispatch, persistence, hosted-demo boundaries, or capability declarations, include a regression test that demonstrates the intended contract.

## Capability-contract rules

[`capabilities.json`](capabilities.json) is the machine-readable source of truth for what LANimals currently claims.

The three supported states are:

- `implemented_tested` — supported runtime behavior with automated contract coverage;
- `implemented_local_runtime` — implemented behavior that depends on local Linux/network state or optional credentials;
- `experimental_legacy` — preserved research code outside the supported operator path.

A pull request that changes a claimed capability should update the implementation, tests, and documentation together. If those surfaces disagree, the change is not complete.

## Pull request expectations

Keep pull requests narrow and reviewable.

A useful PR description should state:

1. the observed problem;
2. the smallest change that addresses it;
3. the security/scope impact, if any;
4. what behavior is intentionally unchanged;
5. the tests or smoke checks used to validate the change.

Avoid mixing unrelated cleanup with behavior changes.

If a bug was discovered in a trust boundary or operator workflow, prefer a regression test that fails on the previous behavior and passes on the proposed fix.

## Independent validation

External verification is especially useful. See [Issue #21](https://github.com/GnomeMan4201/LANimals/issues/21) for a bounded fresh-install and scope-contract replication checklist.

A successful independent report strengthens confidence in the documented supported path; it does not prove compatibility with every network, distribution, or optional integration.

## Review standard

A contribution is ready when another reviewer can determine **what changed, what contract it affects, how it was validated, and what it does not prove** without relying on private context.
