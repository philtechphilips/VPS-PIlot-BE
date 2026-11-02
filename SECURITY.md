# Security policy

VPSPilot runs with a lot of access: the control plane holds credentials for
your servers and databases, and its agent has a root helper on every server.
Reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/philtechphilips/VPS-PIlot-BE/security/advisories/new)**
(this repository's *Security* tab). Don't open a public issue.

Include what you found, how to reproduce it and what it lets an attacker do.
You'll get a reply within a week. Once a fix is released we'll publish an
advisory and credit you, unless you'd rather not be named.

## Supported versions

Fixes go into the latest release on `main`. Upgrade the control plane with
`sudo vpspilot upgrade`; it also upgrades the agent on the same server, and
agents elsewhere upgrade by re-running their install command.

## Scope

In scope: this repository, meaning the API, the agent and its privileged
helper, the installer and the `vpspilot` command. The dashboard lives in
[Vps-Pilot](https://github.com/philtechphilips/Vps-Pilot) and has its own
policy.

Especially interesting:

- escaping the agent's fixed operations (running arbitrary commands as root,
  reading or writing outside an app's own files);
- reaching one server's data or jobs with another server's agent token;
- signing in, or acting as an admin, without the password and second factor;
- reading stored secrets (environment values, database passwords, backup
  keys) without access to the encryption key.

Out of scope: reports that need someone who is already an admin, denial of
service by flooding, and findings from automated scanners without a way to
exploit them.

## How the code is kept safe

Every push and a weekly scheduled run lint and test the code and scan it
with [Trivy](https://trivy.dev): dependencies, committed secrets, the
Dockerfile, and the built image's OS and Python packages. High and critical
issues with a fix fail the build. Dependabot opens pull requests for
updates weekly.
