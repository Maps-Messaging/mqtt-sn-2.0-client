# Conformance status

## Normative baseline

The test suite is pinned to:

**MQTT-SN 2.0 Committee Specification Draft 01, 14 August 2026**

Authoritative OASIS document:

https://docs.oasis-open.org/mqtt/mqtt-sn/v2.0/csd01/mqtt-sn-v2.0-csd01.md

Pinned OASIS source:

https://github.com/oasis-tcs/mqtt/tree/0dae5066d123d068ddca2ddb861ce8858aafee92/mqtt-sn-2.0

The repository does not test against a moving `main` branch. A draft change
requires an explicit baseline update and review.

## What "aligned" means here

The implementations are designed against the pinned CSD01 packet formats,
state rules, flow-control rules, authentication exchange, discovery,
encapsulation and protection schemes.

The suite contains independent implementations and shared vectors so a bug in
one implementation is less likely to become the definition of correct
behaviour.

However, **this repository does not currently claim an OASIS certification or a
formal 100% conformance designation**. OASIS has not published MQTT-SN 2.0 as a
final Standard, and the repository still tracks closure of the complete
normative-requirement matrix.

See [../COMPLETENESS.md](../COMPLETENESS.md) and
`shared/requirements.json` for the detailed implementation/requirement status.

## Current coverage

The suite currently covers, among other areas:

- MQTT-SN packet framing and both Length formats;
- defined/reserved control packet types;
- UTF-8 and topic validation;
- CONNECT/CONNACK;
- generic enhanced authentication and AUTH continuation;
- re-authentication;
- PUBLISH QoS flows;
- REGISTER/SUBSCRIBE/UNSUBSCRIBE;
- PING and Keep Alive;
- sleeping/awake client flows;
- gateway discovery packet formats;
- Connection and Forwarder Encapsulation;
- Protection Encapsulation;
- standard CSD01 HMAC, CMAC, AES-CCM, AES-GCM and ChaCha20/Poly1305 schemes;
- one-outstanding-request flow control;
- retry handling and caller-driven timers;
- transport-neutral input/output buffering;
- Java UDP integration.

## Test requirement references

Tests should cite the narrowest applicable CSD01 requirement identifier, for
example:

```text
MQTT-SN-2.1.2-1
MQTT-SN-3.1.2.3-1
MQTT-SN-4.11.1-3
```

Where the draft provides no numbered requirement, tests cite the relevant
section.

## Updating the baseline

When OASIS publishes a newer MQTT-SN 2.0 draft:

1. pin the new OASIS source commit;
2. diff the normative statements;
3. update `shared/requirements.json`;
4. update packet/state/provider implementations;
5. update shared vectors;
6. run every language suite;
7. only then update [../SPECIFICATION.md](../SPECIFICATION.md).
