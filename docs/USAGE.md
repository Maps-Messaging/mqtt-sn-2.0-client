# Using the MQTT-SN 2.0 Client Suite

This repository provides MQTT-SN 2.0 client implementations for C, C++, Java,
Python and Arduino.

## Specification reference

All implementations target the same pinned normative baseline:

- **MQTT-SN 2.0 Committee Specification Draft 01 (CSD01)**
- document date: **14 August 2026**
- authoritative OASIS publication:
  https://docs.oasis-open.org/mqtt/mqtt-sn/v2.0/csd01/mqtt-sn-v2.0-csd01.md
- OASIS source repository:
  https://github.com/oasis-tcs/mqtt
- pinned source commit:
  `0dae5066d123d068ddca2ddb861ce8858aafee92`

As of 7 October 2026, the August 2026 CSD01/working-draft publication remains
the latest public MQTT-SN 2.0 draft located in the OASIS MQTT TC publication
stream. MQTT-SN 2.0 is still progressing through the OASIS standards process;
CSD01 is not a final OASIS Standard.

See [../SPECIFICATION.md](../SPECIFICATION.md) for the reproducible baseline and
[CONFORMANCE.md](CONFORMANCE.md) for the conformance statement.

## Choosing an implementation

| Implementation | Best fit | Implementation model |
|---|---|---|
| C | Embedded/native applications and constrained runtimes | Canonical native implementation |
| C++ | C++ applications wanting a typed API | Thin wrapper over C |
| Java | JVM applications and MapsMessaging validation | Independent implementation |
| Python | Test tooling, scripting and independent validation | Independent implementation |
| Arduino | Microcontrollers | Compiles the canonical C core |

## Architecture

The protocol core is transport-neutral.

```text
UDP / serial / LoRa / BLE / DTLS / other transport
                  |
                  v
             inbound bytes
                  |
                  v
       codec + session controller
                  |
                  v
            outbound bytes
                  |
                  v
             application
```

The application owns transport I/O. The protocol implementation owns packet
encoding/decoding, state, flow control, Packet Identifiers and protocol rules.

Java additionally provides a small UDP adapter for test/client convenience.

## Common workflow

A normal client does the following:

1. create a session/client controller;
2. allocate a Packet Identifier;
3. encode CONNECT;
4. validate/track CONNECT before transmitting it;
5. feed CONNACK/AUTH responses back into the session;
6. send PUBLISH/SUBSCRIBE/etc. buffers using the same pattern;
7. drive retry and Keep Alive timers using the application's clock;
8. encode DISCONNECT when the session is finished.

For enhanced authentication, see [AUTHENTICATION.md](AUTHENTICATION.md).

For protected packets, see [../PROTECTION.md](../PROTECTION.md).

## Java

Core Maven coordinates:

```xml
<dependency>
  <groupId>io.mapsmessaging</groupId>
  <artifactId>mqtt-sn-2-client</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Optional Bouncy Castle protection provider:

```xml
<dependency>
  <groupId>io.mapsmessaging</groupId>
  <artifactId>mqtt-sn-2-client-protection-bc</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

See [../java/README.md](../java/README.md).

## C

```bash
cmake -S c -B build/c
cmake --build build/c
ctest --test-dir build/c --output-on-failure
```

Link the `mqttsn2` target.

When OpenSSL 3 is available, the optional `mqttsn2_openssl` target provides
the standard CSD01 protection schemes.

See [../c/README.md](../c/README.md).

## C++

```bash
cmake -S cpp -B build/cpp
cmake --build build/cpp
ctest --test-dir build/cpp --output-on-failure
```

Link `mqttsn2_cpp`. When OpenSSL is available,
`mqttsn2_cpp_openssl` provides the optional protection-provider wrapper.

See [../cpp/README.md](../cpp/README.md).

## Python

```bash
cd python
python -m pip install -e .
```

For the standard crypto provider:

```bash
python -m pip install -e ".[crypto]"
```

See [../python/README.md](../python/README.md).

## Arduino

Use the `arduino/` directory as an Arduino library and include:

```cpp
extern "C" {
#include <mqttsn.h>
}
```

Arduino compiles the same C protocol/authentication/protection-envelope core.

See [../arduino/README.md](../arduino/README.md).

## Running the conformance suite

From the repository:

```bash
cmake -S c -B build/c
cmake --build build/c
ctest --test-dir build/c --output-on-failure

cmake -S cpp -B build/cpp
cmake --build build/cpp
ctest --test-dir build/cpp --output-on-failure

mvn --batch-mode clean verify

cd python
python -m pip install -e ".[test]"
python -m pytest
```

GitHub Actions runs the same language families plus an Arduino Uno compile.
Buildkite is used for the Java release/snapshot workflow.
