# Security Policy

## Authorized use only

HexaCore is an offensive-security tool built for **authorized penetration testing** — systems you
own or have **explicit written permission** to test. Using it against systems without authorization
is illegal in most jurisdictions and is not a supported use case.

The platform enforces guardrails (deny-by-default scope, a required named authorization before any
engagement starts, human approval for exploit-class actions, a kill switch, and an append-only audit
log). These reduce accidental out-of-scope activity — they do **not** grant you authorization. That
is always your responsibility.

## Reporting a vulnerability

If you find a security issue **in HexaCore itself** (for example, a way to bypass the scope validator
or approval gate, an authentication flaw, or a secrets-handling problem), please report it privately:

- Open a **GitHub Security Advisory** on this repository (Security tab → "Report a vulnerability"), or
- Email the maintainer.

Please do **not** open a public issue for a security vulnerability until it has been addressed.

Include, where possible:
- what the issue is and where in the code,
- steps to reproduce,
- the impact (what a bad actor could do), and
- any suggested fix.

## Scope of this policy

This policy covers defects in the HexaCore platform code. It does **not** cover findings that
HexaCore produces about *your* targets — those belong in your engagement report, not here.

## Handling secrets

- Your `.env` (JWT signing secret, login passwords) is git-ignored and must never be committed.
- Rotate the default passwords and the JWT secret before any non-local deployment.
- The bundled AI model runs locally; no scan data leaves your machine.
