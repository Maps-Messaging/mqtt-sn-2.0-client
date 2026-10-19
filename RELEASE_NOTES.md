# MQTT-SN 2.0 Client Suite 0.2.0

Release date: 19 October 2026. Changes since 0.1.0; tracked by MSG-325.

This release completes connected authentication renewal and repeated sleep requests in the Java, Python and native client implementations. The protocol baseline remains OASIS MQTT-SN 2.0 CSD01, source revision `0dae5066d123d068ddca2ddb861ce8858aafee92`.

## Authentication renewal

- Start reauthentication with AUTH reason 0x19 and continue using fresh packet identifiers and reason 0x18.
- Accept final AUTH success and validate the mechanism's final authentication data. Initial authentication still finishes with CONNACK.
- Keep the authentication method consistent and require successful initial authentication before renewal.
- Pause other client traffic while renewal is in progress. AUTH is not retransmitted.
- Add Java and Python exchange handling, C state and exchange validation, and C++ forwarding APIs. Arduino uses the updated C core.

## Sleep renewal

- Send SLEEPREQ while already ASLEEP without changing to an awake state.
- Retry a SLEEPREQ after a lost SLEEPRESP while preserving its packet identifier and contents.
- Remember accepted sleep duration, honour server-suggested values and retain the previous accepted duration when renewal is rejected.
- Reset renewal bookkeeping when a new connection begins.

## Compatibility

**Breaking native ABI change:** C client and authentication-exchange structures have grown. Rebuild C, C++ and Arduino consumers against the new headers and implementation. Do not mix 0.1.0 native objects with 0.2.0 headers.

The Java additions are compatible with existing applications. Java 21 remains required. The optional protection module remains separate from the core client.

Maven coordinates:

- `io.mapsmessaging:mqtt-sn-2-client:0.2.0`
- `io.mapsmessaging:mqtt-sn-2-client-protection-bc:0.2.0`

## Validation and scope

Client validation passed 152 Java tests, 115 Python tests and seven native C/C++ test executables, with additional Arduino forwarding-source host checks. Server integration exercises the actual Java UDP client for successful and failed SCRAM renewal, timeout, method continuity, paused publications, sleep renewal, lost-response retry and queued delivery. Matthew confirmed the server tests green on Windows after the directory-sync portability fix.

This is the completed implementation milestone for the current draft scope, not certification against a final MQTT-SN 2.0 standard. Per-language limits and optional transport/crypto requirements remain documented in [COMPLETENESS.md](COMPLETENESS.md). See [authentication](docs/AUTHENTICATION.md) and [sleep renewal](docs/SLEEP_RENEWAL.md) for API guidance.

---

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
