# Security policy

## Reporting a vulnerability

If you find a security issue in the `obsideo-provider` binary or in the
network protocol, please report it privately first. Public disclosure before
a fix is in operators' hands risks active exploitation against running
providers.

**Preferred channel:** GitHub's private vulnerability reporting on this
repository (Security tab → Report a vulnerability). This delivers the report
to maintainers privately and creates a tracked thread.

**Alternative:** Direct message Reg on the operator Telegram chat. Note that
DMs are ephemeral; a GitHub private report is preferred for anything that
needs a paper trail.

## What's in scope

- The `obsideo-provider` binary in this repository
- The network protocol it speaks (described in
  [obsideo-protocol](https://github.com/Regan-Milne/obsideo-protocol))
- Interactions with the coordinator and other providers

## What's out of scope

- Vulnerabilities in upstream Go modules — report to those projects directly
- Configuration mistakes by individual operators (open ports, weak system
  passwords, misconfigured firewalls)
- Issues in the customer's own machine or SDK installation
- Theoretical attacks against AES-256-GCM, Ed25519, or other standard
  primitives without a concrete exploitation path
- Denial-of-service attacks that require resources comparable to the network
  itself

## Architecture and threat model

For the design's threat model — what each party in the system can and cannot
do, what trust assumptions exist, and what's deliberately out of scope of
the protocol's guarantees — see
[obsideo-protocol/ARCHITECTURE.md](https://github.com/Regan-Milne/obsideo-protocol/blob/main/ARCHITECTURE.md),
specifically §8 (Threat model).

## Response expectations

This is alpha software running a small live network. Practical response
windows:

- Acknowledgement of report: within 72 hours
- Initial assessment: within one week
- Coordinated disclosure window: typically 30–90 days from confirmed report,
  depending on severity and whether a fix is available

Critical issues affecting the network's confidentiality (the v2 E2E property)
or integrity (provider data corruption that the protocol can't detect) take
priority over everything else.

## Past advisories

None published. This file will be updated when one is.
