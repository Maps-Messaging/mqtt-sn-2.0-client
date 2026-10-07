# Protection Extension Architecture

MQTT-SN 2.0 Protection Encapsulation is implemented as an extension layer rather
than part of the core packet codec.

This is deliberate. Protection Encapsulation is new in MQTT-SN 2.0 and has
changed during draft development. The transport-neutral packet/session core must
not depend on any particular protection scheme, cryptographic library, key
store, nonce source, hardware module, or draft-specific algorithm set.

## Responsibilities

The protection envelope layer owns:

- Protection Encapsulation framing;
- Protection Flags parsing and validation;
- Sender Identifier and Random fields;
- Cryptographic Material length rules;
- Monotonic Counter length rules;
- authentication-tag length flag rules;
- reserved protection-scheme rejection;
- preservation of the exact authenticated prefix bytes;
- validation that exactly one MQTT-SN packet is protected;
- rejection of Forwarder Encapsulation as a protected inner packet.

The protection provider owns:

- support for one or more Protection Scheme identifiers;
- whether a scheme is authentication-only or AEAD;
- nominal or provider-defined authentication-tag size;
- protected-packet size;
- key lookup and key derivation;
- HMAC/CMAC/AEAD processing;
- nonce/IV derivation;
- authentication verification;
- interaction with software or hardware cryptographic providers.

## Provider-defined schemes

The API intentionally supports provider-defined scheme ranges from CSD01.
Future draft changes can therefore be implemented by adding or replacing a
provider without changing the generic MQTT-SN packet codec.

## No implicit crypto provider

The core does not silently choose a cryptographic implementation. A caller must
supply a provider explicitly.

This avoids binding:

- C to OpenSSL, mbedTLS, wolfSSL, or another library;
- Arduino to a desktop crypto dependency;
- Java to a particular JCE provider;
- Python to a particular third-party package.

Reference/provider implementations can be added independently and tested
against specification vectors.

## Cross-language model

- C: callback-based `mqttsn_protection_provider_t`
- C++: thin virtual-interface wrapper over the C provider callbacks
- Java: `ProtectionProvider` extension interface
- Python: `ProtectionProvider` protocol
- Arduino: canonical C provider API

The envelope APIs preserve the same separation in every implementation.

## Specification baseline

MQTT-SN 2.0 CSD01, 14 August 2026, section 3.17.

The protection API and tests currently cover the structural requirements around
field lengths, reserved values, protected-packet restrictions, provider
selection, tag sizing and authenticated-prefix handling. Concrete
HMAC/CMAC/AEAD providers remain separate implementation work.


## Standard provider implementations

Concrete standard-scheme providers are optional modules:

### Java

Artifact:

```text
io.mapsmessaging:mqtt-sn-2-client-protection-bc:0.1.0-SNAPSHOT
```

This module depends on the core Java client and Bouncy Castle. The core
`mqtt-sn-2-client` artifact itself has no Bouncy Castle dependency.

### Python

Install the optional crypto extra:

```bash
pip install "maps-mqtt-sn-2-client[crypto]"
```

The base Python package does not require `cryptography`.

### C

When OpenSSL 3 is available, CMake creates the optional:

```text
mqttsn2_openssl
```

target. The base `mqttsn2` target has no OpenSSL dependency.

### C++

When the C OpenSSL provider target is available, CMake also exposes:

```text
mqttsn2_cpp_openssl
```

The ordinary `mqttsn2_cpp` target remains a crypto-backend-free wrapper.

### Arduino

The Arduino library exposes the generic C protection-provider ABI but does not
force a desktop crypto backend onto embedded targets. A board-specific software
or hardware crypto provider can implement the same callbacks.

## Standard schemes implemented by the reference providers

The Bouncy Castle, pyca/cryptography and OpenSSL providers implement:

- 0x00 HMAC-SHA256
- 0x01 HMAC-SHA3-256
- 0x02 CMAC-128
- 0x03 CMAC-192
- 0x04 CMAC-256
- 0x40 AES-CCM-64-128
- 0x41 AES-CCM-64-192
- 0x42 AES-CCM-64-256
- 0x43 AES-CCM-128-128
- 0x44 AES-CCM-128-192
- 0x45 AES-CCM-128-256
- 0x46 AES-GCM-128-128
- 0x47 AES-GCM-128-192
- 0x48 AES-GCM-128-256
- 0x49 ChaCha20/Poly1305

The providers derive the CCM nonce and GCM/ChaCha IV/nonce from SHA-256 of the
exact authenticated prefix, truncated as required by CSD01. For
authentication-only schemes, the MAC covers the exact authenticated prefix
followed by the protected MQTT-SN packet. Truncated authentication tags use the
leftmost bytes.

Provider-defined scheme ranges are deliberately not implemented by the
standard providers; custom providers may use them.

## Cross-backend vectors

`shared/protection-provider-vectors.json` contains fixed construction vectors
for every standard CSD01 protection scheme. OpenSSL, Bouncy Castle and
pyca/cryptography tests use the same key/prefix/plaintext construction and must
produce matching protected bytes and tags.
