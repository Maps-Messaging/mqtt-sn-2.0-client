# MQTT-SN 2.0 C++ Client

The C++ API is a thin type-safe wrapper over the canonical C implementation. It
does not duplicate MQTT-SN protocol logic.

Normative reference:
https://docs.oasis-open.org/mqtt/mqtt-sn/v2.0/csd01/mqtt-sn-v2.0-csd01.md

## Build

```bash
cmake -S cpp -B build/cpp
cmake --build build/cpp
ctest --test-dir build/cpp --output-on-failure
```

Link against `mqttsn2_cpp`.

When OpenSSL is available, `mqttsn2_cpp_openssl` adds the optional standard
protection provider.

## Basic CONNECT

```cpp
#include <mqttsn/mqttsn.hpp>

mqttsn::Session session;
auto packetId = session.nextPacketIdentifier();

mqttsn::ConnectOptions options{
    true,
    false,
    false,
    packetId,
    60,
    0,
    "client-1"};

auto connect = mqttsn::Codec::encodeConnect(options);
session.trackOutbound(connect);
transportSend(connect);
```

## Authentication

Include:

```cpp
#include <mqttsn/auth.hpp>
```

Implement `mqttsn::AuthenticationMechanism` for the mechanism you need. The
mechanism can wrap SASL, SCRAM, Kerberos, a secure element, or a custom method.
The core does not require SASL.

See [../docs/AUTHENTICATION.md](../docs/AUTHENTICATION.md).

## Protection

Include `mqttsn/protection_openssl.hpp` and link
`mqttsn2_cpp_openssl` when using the optional OpenSSL provider.

See [../PROTECTION.md](../PROTECTION.md).
