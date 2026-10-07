# MQTT-SN 2.0 C Client

The C implementation is the canonical native MQTT-SN 2.0 implementation in
this repository.

Normative reference:
https://docs.oasis-open.org/mqtt/mqtt-sn/v2.0/csd01/mqtt-sn-v2.0-csd01.md

## Build

```bash
cmake -S c -B build/c
cmake --build build/c
ctest --test-dir build/c --output-on-failure
```

Link against `mqttsn2`.

If OpenSSL 3 is present, CMake also builds `mqttsn2_openssl`.

## Headers

```c
#include <mqttsn/mqttsn.h>
#include <mqttsn/packets.h>
#include <mqttsn/client.h>
#include <mqttsn/auth.h>
#include <mqttsn/protection.h>
```

OpenSSL protection provider:

```c
#include <mqttsn/protection_openssl.h>
```

## Encoding CONNECT

```c
uint8_t output[256];
size_t written = 0;

static const uint8_t client_id[] = "client-1";

mqttsn_connect_options_t options = {
    .clean_start = 1,
    .packet_identifier = 1,
    .keep_alive = 60,
    .maximum_packet_size = 0,
    .client_identifier = client_id,
    .client_identifier_length = sizeof(client_id) - 1
};

mqttsn_status_t status =
    mqttsn_encode_connect(&options, output, sizeof(output), &written);
```

The transport sends `output[0..written)`.

## Authenticated CONNECT

Authentication remains mechanism-agnostic:

```c
static const uint8_t method[] = "SCRAM-SHA-256";

options.authentication_method = method;
options.authentication_method_length = sizeof(method) - 1;
options.authentication_data = initial_response;
options.authentication_data_length = initial_response_length;
```

For challenge/response implement `mqttsn_auth_mechanism_t` and drive it using
`mqttsn_auth_exchange_t`.

See [../docs/AUTHENTICATION.md](../docs/AUTHENTICATION.md).

## Decoding input

Use `mqttsn_decode_packet` for one packet or `mqttsn_process_input` for a
buffer containing multiple complete packets.

The decoder does not retain the input buffer.

## Session state

`mqttsn_client_t` tracks:

- Packet Identifiers;
- CONNECT/CONNACK state;
- Active/Asleep/Awake states;
- request/reply correlation;
- one-outstanding-request flow control.

Call `mqttsn_client_track_outbound` before sending and
`mqttsn_client_track_inbound` for server packets.

## Timers

`mqttsn_retry_timer_t` and `mqttsn_keep_alive_timer_t` are driven with
caller-supplied time values. The library creates no threads and sleeps nowhere.

## Protection

Protection Encapsulation uses the generic provider ABI in
`mqttsn/protection.h`.

`mqttsn2_openssl` is an optional provider implementing the standard CSD01
HMAC/CMAC/CCM/GCM/ChaCha schemes. The core library does not depend on OpenSSL.
