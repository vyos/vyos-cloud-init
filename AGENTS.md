# AGENTS.md

## Project purpose
VyOS-flavored fork of canonical `cloud-init`. Configures VyOS images on first boot in cloud environments (AWS, Azure, GCP, OpenStack, etc.) using upstream datasource handlers.

## Tech stack
- Python (≥3.x). Upstream `cloud-init` codebase.
- Build: `setup.py` + `pyproject.toml` (black 79-char line length, isort black profile). `Makefile` for common dev tasks.
- Tests: `tox.ini`, `pytest` via `conftest.py`. Multiple `*-requirements.txt` files (`requirements.txt`, `test-requirements.txt`, `integration-requirements.txt`, `doc-requirements.txt`).
- Debian packaging in `packages/`.

## Build / test / run
```
pip install -r requirements.txt -r test-requirements.txt
tox                                # full test matrix
pytest tests/unittests              # unit tests only
make                                # see in-repo Makefile targets
# Debian package built indirectly via vyos-build-packages.
```

## Repository layout
- `cloudinit/` — core Python package (datasources, handlers, modules).
- `config/` — default config files installed under `/etc/cloud/`.
- `templates/` — Jinja2 templates rendered at boot.
- `systemd/`, `sysvinit/`, `upstart/`, `udev/`, `bash_completion/` — init system glue.
- `tests/` — unit + integration tests.
- `tools/` — helper scripts.
- `packages/` — packaging templates (Debian, RPM/SUSE, bddeb/brpm scripts).
- `snapcraft.yaml` — snap packaging descriptor (repo root).
- `doc/` — Sphinx documentation source.
- `setup.py`, `pyproject.toml`, `tox.ini`, `conftest.py`.
- Vendored upstream license files: `LICENSE-Apache2.0`, `LICENSE-GPLv3`.

## Cross-repo context
- Consumed by `vyos/vyos-build` as one of the 14 source packages in an internal repository. Produces the `cloud-init` `.deb` shipped inside the VyOS ISO.
- Companion to an internal repository (Azure-specific agent) and an internal repository (SaltStack agent) for cloud-side configuration.
- VyOS-specific datasources may interact with `vyos-1x` config-tree primitives at runtime.

## Conventions
- Commit/PR title: `component: T12345: description` (Phorge task ID at https://vyos.dev). Enforced via inherited reusables.
- Workflows: `pr-mirror-repo-sync.yml`, `trigger-rebuild-repo-package.yml`, `cla-check.yml`, `stale.yml` (uses `vyos/.github@production` reusables).
- License: dual Apache-2.0 / GPL-3 (inherited from upstream `cloud-init`).
- Default branch: `rolling`. Pull from upstream `canonical/cloud-init` via merge or rebase, preserve VyOS-specific deltas.

## Notes for future contributors
- Keep VyOS-specific changes minimal and clearly delineated to ease upstream merges.
- After merging a PR, the `trigger-rebuild-repo-package.yml` workflow fires a REST `workflow_dispatch` into `$REMOTE_OWNER/vyos-build-packages` (REMOTE_OWNER = the private side) to rebuild the Debian package as `vyosbot`.
- Cloud-init's upstream test suite is heavy; running `pytest tests/unittests` is usually sufficient for small VyOS-side patches.
