# Implementation completeness

This matrix is intentionally conservative. A packet being present in the packet-type
catalogue or supported by the generic frame encoder does **not** mean its packet-specific
fields and operational behaviour are implemented.

Specification baseline: MQTT-SN 2.0 CSD01, 14 August 2026.

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
| AUTH | Generic | Generic | Generic | Generic | Shared C |
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
| DISCONNECT | Generic | Generic | Generic | Generic | Shared C |
| SLEEPREQ | Typed encode | Generic | Typed encode | Typed encode | Shared C |
| SLEEPRESP | Typed decode | Generic | Typed decode | Typed decode | Shared C |
| WAKEUP | Typed encode | Generic | Typed encode | Typed encode | Shared C |
| PUBWOS | Generic | Generic | Generic | Generic | Shared C |
| ADVERTISE | Generic | Generic | Generic | Generic | Shared C |
| SEARCHGW | Generic | Generic | Generic | Generic | Shared C |
| GWINFO | Generic | Generic | Generic | Generic | Shared C |
| Forwarder Encapsulation | Generic | Generic | Generic | Generic | Shared C |
| Connection Encapsulation | Generic | Generic | Generic | Generic | Shared C |
| Protection Encapsulation | Generic | Generic | Generic | Generic | Shared C |
| Client state transitions | Implemented foundation | Missing wrapper | Missing | Missing | Shared C |
| One-outstanding-request flow control | Implemented foundation | Missing wrapper | Missing | Missing | Shared C |
| Packet-id allocation | Implemented foundation | Missing wrapper | Missing | Missing | Shared C |
| Retry exhaustion state handling | Implemented foundation | Missing wrapper | Missing | Missing | Shared C |
| Retry timer/backoff scheduler | Missing | Missing | Missing | Missing | Missing |
| Keep-alive timer scheduler | Missing | Missing | Missing | Missing | Missing |
| Session persistence | Missing | Missing | Missing | Missing | Missing |
| Authentication exchange state | Partial/generic | Missing | Missing | Missing | Partial/generic |
| Protection cryptography | Missing | Missing | Missing | Missing | Missing |
| Gateway discovery behaviour | Missing | Missing | Missing | Missing | Missing |

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
- retry exhaustion and packet identifier allocation.

### C++

The C++ implementation deliberately contains no independent protocol engine. Tests therefore
verify wrapper wire results, boundary handling, error propagation, and delegation to C.

### Java

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
- UTF-8 and topic wildcard rules.

### Python

Pytest mirrors the Java/C wire-level boundary, malformed-input, topic, QoS, acknowledgement,
PING and SLEEP cases.

### Arduino

Arduino intentionally shares the C implementation. CI compiles the Arduino library/example
against the same C sources; protocol behaviour is tested in the C suite rather than copied
into an Arduino-specific test implementation.

## Before calling a language implementation complete

At minimum, the following remain required:

1. typed codecs for every control packet applicable to that client;
2. client state/flow controller in Java and Python and a C++ wrapper for the C controller;
3. retry, keep-alive and sleep timers driven by caller-supplied time rather than transport code;
4. AUTH packet codecs and authentication exchange state;
5. DISCONNECT typed codec and reason/session-expiry handling;
6. PUBWOS and gateway discovery codecs/behaviour;
7. Connection, Forwarder and Protection Encapsulation;
8. protection scheme implementation/tests where required for claimed conformance;
9. requirement-by-requirement traceability in `shared/requirements.json`;
10. integration/conformance tests runnable against MapsMessaging without MapsMessaging-specific expected behaviour.

Until those are complete, this repository should describe individual areas as implemented,
not claim full MQTT-SN 2.0 client conformance.
