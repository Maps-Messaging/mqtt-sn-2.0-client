# MQTT-SN 2.0 Arduino Client

The Arduino library compiles the canonical C MQTT-SN implementation for
microcontroller use.

Normative reference:
https://docs.oasis-open.org/mqtt/mqtt-sn/v2.0/csd01/mqtt-sn-v2.0-csd01.md

## Include

```cpp
extern "C" {
#include <mqttsn.h>
}
```

See `examples/BufferClient/BufferClient.ino`.

## Transport

The library is not tied to `WiFiUDP`, Ethernet, Serial, LoRa or another
transport.

Your sketch:

1. receives bytes from the selected transport;
2. passes them into `mqttsn_decode_packet` or `mqttsn_process_input`;
3. encodes outbound packets into a caller-owned buffer;
4. sends that buffer using the transport.

## Authentication

The Arduino package exposes the canonical C authentication provider API via:

```cpp
#include <mqttsn/auth.h>
```

Implement the callbacks for the mechanism appropriate to the device. This can
be a compact challenge/response implementation or a hardware-backed mechanism.
SASL is not required.

## Protection

The generic C Protection Encapsulation/provider ABI is available. No desktop
crypto implementation is forced onto Arduino.

A board-specific crypto implementation or secure element can implement the same
provider callbacks.
