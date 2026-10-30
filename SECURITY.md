# Security policy

Kallara holds the keys to other people's data, so we treat every report as urgent.

## Reporting a vulnerability

Do **not** open a public issue. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

Include what you found, how to reproduce it, and what an attacker could do with it. We aim to
acknowledge within 2 working days and to agree a disclosure date with you.

## Scope

This repository holds the code Kallara customers run on their own machines (agent, CLI, SDKs), the
API contract, and the specifications with their conformance vectors. Reports about the hosted
platform are welcome through the same channel.

The key material in `conformance/vectors/` is published test data. Finding it is not a
vulnerability; finding it accepted by a production Kallara deployment would be.
