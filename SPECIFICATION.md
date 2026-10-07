# MQTT-SN 2.0 specification baseline

This repository uses the OASIS MQTT-SN 2.0 **Committee Specification Draft 01 (CSD01), 14 August 2026** as its normative baseline.

## Pinned source

OASIS TC source repository:

- Repository: `oasis-tcs/mqtt`
- Commit: `0dae5066d123d068ddca2ddb861ce8858aafee92`
- Source tree: `mqtt-sn-2.0/`
- Draft source: `mqtt-sn-2.0/prose/`

The draft front matter identifies the authoritative CSD01 Markdown publication at:

`https://docs.oasis-open.org/mqtt/mqtt-sn/v2.0/csd01/mqtt-sn-v2.0-csd01.md`

OASIS uploaded the August 2026 HTML draft on 14 August 2026 and PDF revision on 15 August 2026, describing it as containing changes for all closed MQTT-SN issues labelled `Fix added` plus typographical and reference corrections.

## Why the source commit is pinned

MQTT-SN 2.0 is still under development. Referencing only a moving "latest" document would make a conformance result irreproducible. Tests in this repository therefore target the commit above.

When the OASIS draft changes:

1. identify the new source commit and publication stage;
2. review the specification delta;
3. update implementation and vectors;
4. update every affected requirement reference;
5. change this file only when the suite is valid against the new baseline.

## Requirement references

The specification marks automatically testable normative statements using identifiers such as:

`MQTT-SN-2.1.2-1`

Tests should cite those identifiers whenever one exists. Otherwise they must cite the narrowest relevant section.

## Implementation status

The suite now implements the CSD01 packet framing, packet-specific client
codecs, client state/flow control, enhanced authentication exchange,
re-authentication, discovery packets, Connection/Forwarder/Protection
Encapsulation, caller-driven retry/Keep Alive handling, and the standard
CSD01 protection schemes through pluggable providers.

The repository deliberately distinguishes implementation coverage from a formal
100% conformance claim. Full normative closure is tracked in
`shared/requirements.json` and [COMPLETENESS.md](COMPLETENESS.md).

See:

- [docs/USAGE.md](docs/USAGE.md) for client usage;
- [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) for generic enhanced
  authentication and the optional Java SASL adapter;
- [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the conformance statement;
- [PROTECTION.md](PROTECTION.md) for pluggable protection providers.
