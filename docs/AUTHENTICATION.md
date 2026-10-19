# Authentication

MQTT-SN 2.0 CSD01 enhanced authentication is **mechanism agnostic**.

The Authentication Method string identifies the mechanism; Authentication Data
contains opaque mechanism-defined bytes.

The specification explicitly notes that a registered
[SASL](https://datatracker.ietf.org/doc/html/rfc4422) mechanism name is a useful
interoperability choice, but MQTT-SN does **not** require SASL.

This library follows that model.

## Specification rules implemented

The authentication layer follows CSD01 section 4.11.1, including:

- CONNECT starts authentication by setting the Auth flag and supplying
  Authentication Method/Data;
- server continuation uses AUTH reason code `0x18`;
- client continuation uses AUTH reason code `0x18`;
- Authentication Method remains unchanged during the exchange;
- successful CONNACK retains the Authentication Method;
- re-authentication starts with AUTH reason code `0x19`;
- a client that did not start authentication must not invent AUTH traffic.

Relevant normative statements include:

- MQTT-SN-3.1.2.3-1/-2
- MQTT-SN-3.3.2-1
- MQTT-SN-3.3.3-1
- MQTT-SN-4.11.1-1 through -7
- MQTT-SN-4.11.1.1-1/-2

## Generic mechanism contract

Each language exposes the same conceptual mechanism:

```text
method name
initial response
evaluate server challenge -> client response
is exchange complete?
reset/restart for re-authentication
```

The MQTT-SN layer owns packet sequencing and reason codes. The authentication
mechanism owns the contents of Authentication Data.

That allows:

- SASL mechanisms;
- SCRAM implementations;
- Kerberos/GS2;
- MQTT-BASIC / MQTT-ENHANCED adapters;
- hardware-token challenge/response;
- deployment-specific authentication methods.

## Java SASL example

Java includes `SaslAuthenticationMechanism`, an adapter around
`javax.security.sasl.SaslClient`.

A typical MAPS-style integration can create the SASL mechanism using the same
SASL configuration used by the server:

```java
SaslAuthenticationMechanism mechanism =
    new SaslAuthenticationMechanism(() -> createSaslClient());

AuthenticationExchange auth =
    new AuthenticationExchange(mechanism);

int connectId = session.nextPacketIdentifier();
byte[] initialData = auth.initialResponse();

byte[] connect = MqttSnCodec.encodeConnect(
    new ConnectOptions(
        true,
        false,
        false,
        connectId,
        60,
        0,
        "client-1"),
    auth.method(),
    initialData);

session.trackOutbound(connect);
transport.send(connect);
```

When an AUTH packet arrives:

```java
DecodedPacket decoded = MqttSnCodec.decode(ByteBuffer.wrap(received));
AuthPacket challenge = MqttSnCodec.decodeAuth(decoded);

int responseId = session.nextPacketIdentifier();
AuthPacket response =
    auth.continueAuthentication(challenge, responseId);

byte[] encoded = MqttSnCodec.encodeAuth(response);
session.trackInbound(received);
session.trackOutbound(encoded);
transport.send(encoded);
```

When the successful CONNACK arrives:

```java
ConnAck connAck = MqttSnCodec.decodeConnAck(decoded);
auth.acceptConnAck(connAck);
session.trackInbound(received);
```

For re-authentication use a `SaslClient` factory, not a single one-shot
`SaslClient` instance:

```java
var mechanism =
    new SaslAuthenticationMechanism(() -> createSaslClient());

var auth = new AuthenticationExchange(mechanism);

AuthPacket reauth =
    auth.beginReauthentication(session.nextPacketIdentifier());
```

## C

C uses `mqttsn_auth_mechanism_t` callbacks and
`mqttsn_auth_exchange_t`.

Implement callbacks for:

- `initial_response`
- `evaluate_challenge`
- `complete`
- optional `reset`

Set `method` to the mechanism name, such as `SCRAM-SHA-256`, and feed the
opaque challenge/response bytes through the callbacks.

No SASL library is required by the C core.

## C++

C++ exposes `mqttsn::AuthenticationMechanism` and
`mqttsn::AuthenticationExchange` in:

```cpp
#include <mqttsn/auth.hpp>
```

Implement the virtual mechanism methods and let the wrapper delegate MQTT-SN
exchange semantics to the C core.

## Python

Implement the `AuthenticationMechanism` protocol and use
`AuthenticationExchange`:

```python
from mqttsn2 import AuthenticationExchange

auth = AuthenticationExchange(my_mechanism)
initial = auth.initial_response()
```

The mechanism can wrap any Python SASL/SCRAM implementation if desired; the
core package deliberately does not require one.

## Arduino

Arduino exposes the same C callback API via `mqttsn/auth.h`.

This makes it possible to use a board-specific mechanism, secure element or
small custom challenge/response implementation without pulling a desktop SASL
stack onto the microcontroller.


## Completing connected re-authentication (MSG-325)

The initial exchange ends with CONNACK. A subsequent renewal ends with an AUTH
packet whose reason code is `0x00`; it must not establish another connection.
Use `AuthenticationExchange.acceptAuth()` in Java/C++, `accept_auth()` in Python,
or `mqttsn_auth_exchange_accept_auth()` in C to verify the final mechanism data
and mark the exchange inactive. These APIs reject completion before renewal,
a changed method, and an incomplete mechanism. A successfully authenticated
initial exchange is required before starting renewal.

Track every outgoing and incoming packet through the session controller. It
retains the method from CONNECT, matches each server reply to the latest client
AUTH identifier, permits a fresh identifier on continuation, pauses other client
traffic during renewal, and rejects AUTH retransmission. AUTH `0x19` initiates
renewal; subsequent client AUTH packets use `0x18`. CONNACK remains confined to
the initial connection. A transport can reuse an exchange for multiple renewals.

The transport owner must bound the whole exchange with a deadline. On timeout,
DISCONNECT, or final mechanism verification failure, send DISCONNECT with an
appropriate reason when possible, delete the local connection (Java
`session.retryExhausted()`, Python `session.retry_exhausted()`, C
`mqttsn_client_retry_exhausted()`), and dispose/reset the authentication mechanism.
Do not retry AUTH. The core helpers own no socket, scheduler, or automatic retry
loop. Session tracking validates the protocol; `acceptAuth` also validates the
mechanism's final signature/data before the application resumes work.

C and C++ applications must rebuild against the updated headers: the public
client and authentication-exchange structs include additional renewal state.
Arduino forwarding headers and sources compile the canonical C implementation.
