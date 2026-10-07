# MQTT-SN 2.0 Python Client

The Python package is an independent MQTT-SN 2.0 implementation used for
scripting, testing and cross-validation.

Normative reference:
https://docs.oasis-open.org/mqtt/mqtt-sn/v2.0/csd01/mqtt-sn-v2.0-csd01.md

## Install

```bash
cd python
python -m pip install -e .
```

Development/tests:

```bash
python -m pip install -e ".[test]"
python -m pytest
```

Standard crypto provider:

```bash
python -m pip install -e ".[crypto]"
```

## Basic CONNECT

```python
from mqttsn2 import ConnectOptions, Session, encode_connect

session = Session()
packet_id = session.next_packet_identifier()

connect = encode_connect(
    ConnectOptions(
        True,
        False,
        False,
        packet_id,
        60,
        0,
        "client-1",
    )
)

session.track_outbound(connect)
transport.send(connect)
```

## Authentication

Authentication is mechanism-agnostic.

Implement the `AuthenticationMechanism` protocol, then:

```python
from mqttsn2 import AuthenticationExchange, ConnectOptions, encode_connect

auth = AuthenticationExchange(my_mechanism)
initial = auth.initial_response()

connect = encode_connect(
    ConnectOptions(
        True,
        False,
        False,
        packet_id,
        60,
        0,
        "client-1",
        auth.method,
        initial,
    )
)
```

A mechanism may wrap SASL/SCRAM, but the package does not require a SASL
library.

See [../docs/AUTHENTICATION.md](../docs/AUTHENTICATION.md).

## Protection

Install the `crypto` extra and use
`mqttsn2.providers.CryptographyProtectionProvider`.

The core package remains usable without pyca/cryptography.
