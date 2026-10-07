# MQTT-SN 2.0 Client Suite

Transport-neutral MQTT-SN 2.0 reference clients for validating protocol implementations, including MapsMessaging.

> **Specification status:** MQTT-SN 2.0 is not yet an OASIS Standard. This repository is pinned to the OASIS MQTT-SN 2.0 CSD01 draft dated 14 August 2026. See [SPECIFICATION.md](SPECIFICATION.md).

## Design goals

- Strict conformance to the pinned MQTT-SN 2.0 draft.
- No protocol core is tied to UDP, DTLS, serial, LoRa, BLE, TCP, or another transport.
- Inbound bytes are supplied by the application/transport layer.
- Outbound bytes are returned to the application/transport layer.
- Shared protocol vectors keep the independent implementations aligned.
- C is the canonical native implementation.
- C++ is a thin wrapper over C and does not duplicate protocol semantics.
- Arduino uses the C core.
- Java and Python are independent implementations so they can cross-check the native core.

## Repository layout

```text
arduino/       Arduino examples using the C core
c/             Canonical portable C implementation
cpp/           Thin C++ wrapper over the C implementation
java/          Java implementation
python/        Python implementation
shared/        Language-neutral specification data and conformance vectors
SPECIFICATION.md  Exact normative draft baseline
```

## Transport model

The protocol layer does not open sockets or serial ports.

A transport reads bytes by whatever mechanism is appropriate and passes those bytes into a decoder/client. The protocol layer returns encoded MQTT-SN packet bytes; the transport sends them.

This deliberately supports datagram transports such as UDP while not assuming them.

```text
network / radio / serial
          |
          v
     inbound bytes
          |
          v
   MQTT-SN protocol core
          |
          v
     outbound bytes
          |
          v
network / radio / serial
```

## Implementations

| Implementation | Role | Transport dependency |
|---|---|---|
| C | Canonical native core | None |
| C++ | Type-safe wrapper over C | None |
| Arduino | Embedded use of C core | None |
| Java | Independent reference client | None |
| Python | Independent reference client | None |

See [COMPLETENESS.md](COMPLETENESS.md) for the current per-language implementation and test matrix.\n\n## Conformance rules

Every conformance test must identify the MQTT-SN specification requirement or section that establishes the expected result.

Normative `MUST` and `MUST NOT` requirements are treated as hard failures. `SHOULD`, `SHOULD NOT`, and `MAY` behaviour is recorded separately so draft flexibility is not accidentally converted into a requirement.

Specification ambiguity is documented rather than resolved with MapsMessaging-specific behaviour.

## Current foundation

The initial implementation provides:

- the complete MQTT-SN 2.0 control packet type catalogue from section 2.1.3;
- one-byte and three-byte packet length encoding/decoding from section 2.1.2;
- reserved packet-type rejection;
- transport-neutral buffer encode/decode APIs;
- shared wire vectors consumed by implementations as they mature.

Packet-specific field codecs, client state transitions, retry behaviour, sleeping client behaviour, discovery, authentication, and encapsulation conformance are built on top of this foundation.

## Build

### C

```bash
cmake -S c -B build/c
cmake --build build/c
ctest --test-dir build/c --output-on-failure
```

### C++

```bash
cmake -S cpp -B build/cpp
cmake --build build/cpp
ctest --test-dir build/cpp --output-on-failure
```

### Java

```bash
cd java
mvn test
```

### Python

```bash
cd python
python -m pytest
```

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
