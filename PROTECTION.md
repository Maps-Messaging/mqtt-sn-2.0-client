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
