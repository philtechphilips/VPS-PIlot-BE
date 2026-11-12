# Contributing to VPSPilot

Thanks for helping. VPSPilot is two repositories: this one (API, agent,
installer) and [Vps-Pilot](https://github.com/philtechphilips/Vps-Pilot)
(dashboard). A change that needs both gets a pull request in each, linked to
each other.

## Before you start

- **Bugs**: open an issue with what you did, what you expected and what
  happened, plus the versions `sudo vpspilot status` prints.
- **Larger changes** (a feature, a new agent operation, a schema change): open
  an issue first so we can agree on the approach before you build it.
- **Security issues**: never in a public issue. See [SECURITY.md](SECURITY.md).

## Setting up

Follow [Quick start](README.md#quick-start). The tests run on in-memory
SQLite with email captured, so they need no PostgreSQL or API keys. The
[lab](lab/README.md) runs real agents in local VMs.

## Pull requests

- `uv run poe check` (lint, format check and tests) passes. CI runs it, plus
  Trivy on the code and the image.
- Behaviour changes come with tests.
- Schema changes come with an Alembic migration (`uv run poe makemigration
  "..."`) that upgrades and downgrades cleanly.
- The agent runs on Ubuntu 22.04's Python 3.10, so `agent/` can't use newer
  syntax (CI checks). Root work goes through the helper's fixed operations,
  never a command built from user input.
- When the agent changes, bump its version in `app/agent_version.py` and
  `agent/vpspilot_agent/__init__.py`, and gate job types that need it in
  `NEEDS_AGENT` (`app/jobs/service.py`).
- Keep each pull request to one change, and say what it does and why.

## License

Contributions are licensed under the [Apache License 2.0](LICENSE), like the
rest of the project (section 5 of the license).
