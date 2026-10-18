# MQTT-SN 2.0 Client Suite 0.1.0

Version 0.1.0 is the first release of the MapsMessaging MQTT-SN 2.0 reference-client suite. It targets **OASIS MQTT-SN 2.0 Committee Specification Draft 01 (14 August 2026)**, not a final OASIS Standard.

The suite supports interoperability testing and applications that need transport-neutral MQTT-SN 2.0 packet handling.

## Client implementations

- **Java:** A transport-neutral MQTT-SN 2.0 packet codec and client/session model, with a UDP adapter. Maven artifact: `io.mapsmessaging:mqtt-sn-2-client:0.1.0`.
- **Optional Java protection provider:** Maven artifact `io.mapsmessaging:mqtt-sn-2-client-protection-bc:0.1.0`, using Bouncy Castle to support standard Protection Encapsulation schemes. The core Java client does not depend on Bouncy Castle.
- **C:** Portable native protocol core with caller-managed transport input/output.
- **C++:** Thin wrapper around the C implementation.
- **Arduino:** Examples that reuse the C core.
- **Python:** Independent reference implementation with protocol tests.

Only the Java modules are Maven artifacts. Other implementations and the Wireshark dissector are distributed as source in this repository.

## Protocol capabilities

- One-byte and extended three-byte packet lengths, packet-type decoding, reserved-value validation, and packet-specific codecs.
- Connection establishment, publish/subscribe flows, acknowledgements, sleep/wake behaviour, gateway discovery and protocol encapsulation.
- Client state and flow-control foundations, with caller-driven retry and keep-alive handling.
- Enhanced authentication, including challenge/response and re-authentication, plus an optional Java SASL adapter.
- Extensible Protection Encapsulation interfaces and optional cryptographic providers.
- Shared protocol and protection test vectors across languages.

## Reliability improvements and tooling

- Correct byte-array equality and hashing for Java packet and protection models, with regression coverage.
- Refine Java session input handling, wildcard topic validation and protection-codec processing.
- Add authentication edge-case tests for the CSD01 draft.
- Add a Wireshark Lua dissector, sample packet captures and diagnostic tools for MQTT-SN 2.0 CSD01.

## Compatibility and limitations

- **Java 21** or newer is required for the Java client and optional protection provider.
- The implemented semantics target the **August 2026 CSD01 draft**. Later OASIS drafts or an approved standard may change them.
- The suite does not claim complete normative conformance. Typed packet and state-machine coverage varies across languages; session persistence and some higher-level workflow integrations are not implemented.
- The core APIs do not automatically open a network transport. Applications supply a transport integration or use the Java UDP adapter.
- Cryptographic protection requires explicitly configuring a provider.

See [COMPLETENESS.md](COMPLETENESS.md) for the per-language support matrix, [SPECIFICATION.md](SPECIFICATION.md) for the pinned draft, and [docs/USAGE.md](docs/USAGE.md) for examples.
