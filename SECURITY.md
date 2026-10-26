# Security Policy

## Supported versions

REE is pre-alpha. Security fixes are applied to the latest code on `main` and to the latest published release, when one exists. Older pre-release versions are not supported.

## Reporting a vulnerability

Do not open a public issue for a security vulnerability.

Use GitHub's private vulnerability reporting:

<https://github.com/mrsandipmandal/reverse-engineer-everything/security/advisories/new>

If private reporting is unavailable, contact the maintainer listed in [MAINTAINERS.md](MAINTAINERS.md) through GitHub.

Please include:

- affected version or commit;
- operating system and architecture;
- a minimal reproduction;
- impact and attack prerequisites;
- whether untrusted input is required;
- any suggested mitigation.

Do not include live secrets, personal data, or proprietary binaries. Use synthetic fixtures where possible.

## Response

The maintainer aims to acknowledge reports within three business days and to provide a triage decision within seven business days. These are goals, not guarantees.

## Scope

Security-sensitive areas include:

- parsers for untrusted artifacts;
- archive extraction and path handling;
- subprocess execution and isolation;
- evidence integrity and canonicalization;
- MCP and CLI input validation;
- supply-chain and release integrity.

## Safe harbor

Good-faith research on your own systems and artifacts is welcome. Do not test against systems, accounts, or data you do not own or have permission to use. Do not cause disruption, exfiltrate data, or access third-party systems.

## No bug bounty

There is currently no bug bounty program.
