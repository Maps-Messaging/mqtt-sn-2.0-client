# Implementation completeness

This matrix is intentionally conservative. A packet being present in the packet-type
catalogue or supported by the generic frame encoder does **not** mean its packet-specific
fields and operational behaviour are implemented.

Specification baseline: MQTT-SN 2.0 CSD01, 14 August 2026.

See also [PROTECTION.md](PROTECTION.md) for the pluggable Protection Encapsulation architecture.

Legend:

- **Typed**: packet-specific encode/decode API exists and validates implemented field rules.
- **Generic**: only generic frame encode/decode and packet type recognition exist.
- **Wrapped**: C++ delegates to the canonical C implementation.
- **Shared C**: Arduino compiles the canonical C implementation.
- **Missing**: packet-specific implementation remains to be added.

| Protocol area | C | C++ | Java | Python | Arduino |
|---|---|---|---|---|---|
| Generic framing, 1/3-byte length | Typed | Wrapped | Typed | Typed | Shared C |
| Packet type catalogue / reserved rejection | Typed | Wrapped | Typed | Typed | Shared C |
| MQTT-SN UTF-8 validation | Typed | Wrapped indirectly | Typed | Typed | Shared C |
| Topic name/filter validation | Typed | Wrapped indirectly | Typed | Typed | Shared C |
| CONNECT | Typed encode | Wrapped | Typed encode | Typed encode | Shared C |
| CONNACK | Typed decode | Wrapped | Typed decode | Typed decode | Shared C |
| AUTH | Typed | Wrapped | Typed | Typed | Shared C |
| REGISTER | Typed client encode | Generic | Typed client encode | Typed client encode | Shared C |
| REGACK | Generic | Generic | Generic | Generic | Shared C |
| PUBLISH | Typed encode/decode | Generic | Typed encode/decode | Typed encode/decode | Shared C |
| PUBACK/PUBREC/PUBREL/PUBCOMP | Typed common ack | Generic | Typed common ack | Typed common ack | Shared C |
| SUBSCRIBE | Typed encode | Generic | Typed encode | Typed encode | Shared C |
| SUBACK | Typed decode | Generic | Typed decode | Typed decode | Shared C |
| UNSUBSCRIBE | Typed encode | Generic | Typed encode | Typed encode | Shared C |
| UNSUBACK | Typed common ack | Generic | Typed common ack | Typed common ack | Shared C |
| PINGREQ | Typed encode | Generic | Typed encode | Typed encode | Shared C |
| PINGRESP | Typed decode | Generic | Typed decode | Typed decode | Shared C |
| DISCONNECT | Typed | Wrapped | Typed | Typed | Shared C |
| SLEEPREQ | Typed encode | Generic | Typed encode | Typed encode | Shared C |
| SLEEPRESP | Typed decode | Generic | Typed decode | Typed decode | Shared C |
| WAKEUP | Typed encode | Generic | Typed encode | Typed encode | Shared C |
| PUBWOS | Typed | Wrapped | Typed | Typed | Shared C |
| ADVERTISE | Typed | Wrapped | Typed | Typed | Shared C |
| SEARCHGW | Typed | Wrapped | Typed | Typed | Shared C |
| GWINFO | Typed | Wrapped | Typed | Typed | Shared C |
| Forwarder Encapsulation | Typed | Wrapped | Typed | Typed | Shared C |
| Connection Encapsulation | Typed | Wrapped | Typed | Typed | Shared C |
| Protection Encapsulation | Pluggable envelope | Wrapped | Pluggable envelope | Pluggable envelope | Shared C |
| Client state transitions | Implemented foundation | Wrapped | Implemented foundation | Implemented foundation | Shared C |
| One-outstanding-request flow control | Implemented foundation | Wrapped | Implemented foundation | Implemented foundation | Shared C |
| Packet-id allocation | Implemented foundation | Wrapped | Implemented foundation | Implemented foundation | Shared C |
| Retry exhaustion state handling | Implemented foundation | Wrapped | Implemented foundation | Implemented foundation | Shared C |
| Retry timer/backoff scheduler | Caller-driven timer | Wrapped | Caller-driven timer | Caller-driven timer | Shared C |
| Keep-alive timer scheduler | Caller-driven timer | Wrapped | Caller-driven timer | Caller-driven timer | Shared C |
| Session persistence | Missing | Missing | Missing | Missing | Missing |
| Authentication exchange state | Implemented | Wrapped | Implemented + SASL adapter | Implemented | Shared C |
| Protection cryptography | Optional OpenSSL provider | Wrapped OpenSSL provider | Optional Bouncy Castle provider | Optional pyca/cryptography provider | Provider ABI only |
| Gateway discovery behaviour | Codec foundation | Wrapped | Codec foundation | Codec foundation | Shared C |

## Test coverage structure

### C

- framing boundaries and malformed frames;
- UTF-8 and topic validation;
- CONNECT/CONNACK;
- PUBLISH QoS and topic variants;
- SUBSCRIBE/SUBACK;
- acknowledgements;
- PING and SLEEP;
- client state and flow-control transitions;
- retry exhaustion and packet identifier allocation;
- OpenSSL standard protection-provider vectors when OpenSSL 3 is available.

### C++

The C++ implementation deliberately contains no independent protocol engine. Tests therefore
verify wrapper wire results, boundary handling, error propagation, and delegation to C.

### Java

The Java artifact also includes a UDP adapter over the transport-neutral session/controller.

JUnit tests cover:

- every defined and representative reserved packet type;
- short/extended/max packet framing boundaries;
- malformed/truncated packets;
- public option/model validation and defensive copying;
- transport-neutral multi-packet input;
- CONNECT/CONNACK optional fields;
- PUBLISH QoS 0/1/2, aliases, flags and malformed input;
- SUBSCRIBE/SUBACK;
- common acknowledgements;
- PING, SLEEP and WAKEUP;
- UTF-8 and topic wildcard rules;
- Protection Encapsulation structure and all 15 standard Bouncy Castle provider scheme vectors.

### Python

Pytest mirrors the Java/C wire-level boundary, malformed-input, topic, QoS, acknowledgement,
PING, SLEEP, AUTH, DISCONNECT, PUBWOS, gateway discovery, encapsulation, timers and
client state/flow cases, Protection Encapsulation and all 15 standard pyca/cryptography provider scheme vectors.

### Arduino

Arduino intentionally shares the C implementation. CI compiles the Arduino library/example
against the same C sources; protocol behaviour is tested in the C suite rather than copied
into an Arduino-specific test implementation.

## Before calling a language implementation complete

At minimum, the following remain required:

1. typed codecs for every remaining control packet applicable to that client;
2. full behavioural parity and integration coverage for the state/flow controllers;
3. integration of caller-driven retry/keep-alive timers into higher-level client workflows;
4. finish any remaining AUTH reason-code applicability cases in the normative requirement matrix;
5. complete applicable reason-code and session-expiry validation for DISCONNECT;
6. higher-level gateway discovery behaviour where required by the test client;
7. board-specific embedded Protection Providers where required;
8. provider-defined protection schemes only where a deployment needs them;
9. requirement-by-requirement traceability in `shared/requirements.json`;
10. integration/conformance tests runnable against MapsMessaging without MapsMessaging-specific expected behaviour.

Until those are complete, this repository should describe individual areas as implemented,
not claim full MQTT-SN 2.0 client conformance.
