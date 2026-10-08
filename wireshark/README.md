# MQTT-SN 2.0 Wireshark dissector

`mqttsn2.lua` decodes the repository's pinned **14 August 2026 CSD01** draft.
It is a standalone Lua plugin: no Java JAR, compiler, or third-party Lua package
is required. See [SPECIFICATION.md](../SPECIFICATION.md) for the exact source commit.

## Install

1. In Wireshark, open **Help → About Wireshark → Folders** (on macOS, **Wireshark →
   About Wireshark → Folders**).
2. Open the **Personal Lua Plugins** directory; create it if necessary.
3. Copy `mqttsn2.lua` into that directory. Install it only once.
4. Restart Wireshark. Open a capture and select **Analyze → Decode As…** for the
   relevant UDP port, choosing **MQTTSN2**.

The default dedicated UDP port is **1884**. This is a plugin convenience, not a
claim that the draft assigns that port. Change it under **Preferences → Protocols
→ MQTTSN2 → UDP ports**. Use `1883` if that is your server's MQTT-SN v2 port.
The range preference accepts multiple ports and ranges. Select only ports that
carry v2; the plugin does not heuristically classify MQTT-SN 1.2 traffic. Keep
Wireshark's built-in `mqttsn` decoder for 1.2 captures.

To locate plugin folders from the terminal, run `tshark -G folders`.
Wireshark must have Lua enabled. Scripts may be disabled when running as root;
normal desktop use does not require root or changes to Lua security settings.

## Use without installing

Run from the repository root:

```sh
tshark -n -X lua_script:wireshark/mqttsn2.lua \
  -r wireshark/captures/mqttsn2-csd01.pcap
```

For a capture on another port:

```sh
tshark -n -X lua_script:wireshark/mqttsn2.lua \
  -d udp.port==1883,mqttsn2 -r traffic.pcapng
```

Extract selected fields:

```sh
tshark -n -X lua_script:wireshark/mqttsn2.lua \
  -r wireshark/captures/mqttsn2-csd01.pcap \
  -T fields -e frame.number -e mqttsn2.msg_type \
  -e mqttsn2.packet_id -e mqttsn2.topic_name -e mqttsn2.reason_code
```

Useful display filters:

| Filter | Meaning |
|---|---|
| `mqttsn2` | All decoded v2 packets |
| `mqttsn2.msg_type == 0x03` | PUBLISH |
| `mqttsn2.msg_type == 0x0f` | AUTH |
| `mqttsn2.packet_id == 291` | A packet identifier, including nested packets |
| `mqttsn2.topic_name == "a/b"` | A literal topic name |
| `mqttsn2.qos == 2` | QoS 2 |
| `mqttsn2.reason_code >= 0x80` | Error reason codes |
| `mqttsn2.malformed` | Structural/field warnings |
| `mqttsn2.protection.scheme` | Protection envelopes |
| `mqttsn2.unverified` | Protection authentication has not been verified |

## Coverage and limits

- Every CSD01 packet type: CONNECT, CONNACK, PUBLISH and acknowledgements,
  subscriptions, REGISTER/REGACK, AUTH, disconnect, sleep/wake, discovery,
  PUBWOS, and all three encapsulations.
- Short/extended length framing, flags and optional fields, UTF-8 names,
  identifiers, aliases, binary payloads, authentication fields, Will fields,
  session expiry, timers and discovery metadata.
- Recursive Forwarder/Connection Encapsulation, limited to eight nesting levels
  to protect the dissector. This is a defensive implementation limit.
- Protection envelope fields, standard scheme tag boundaries, and inspectable
  authentication-only plaintext. **Tags are never verified.** The generated
  `mqttsn2.protection.verified` field is always false, with an expert note.
- AEAD contents are shown as ciphertext. Provider-defined nominal tag sizes and
  tag code zero are not guessed: the remaining packet/tag bytes are opaque,
  with an expert note. No key management or decryption is implemented.
- One MQTT-SN packet per UDP payload. Extra bytes, invalid lengths and truncated
  fields produce expert errors; no stream reassembly is attempted.
- Packet-level checks only. This is not a complete conformance validator:
  reason-code applicability, sender direction, session lifecycle, negotiated
  limits, topic-alias resolution and request/response correlation are not checked.

CSD01 uses flag-controlled optional fields; it does **not** use MQTT 5's generic
property-length/TLV block. The plugin displays the draft's actual fields.

### Pinned draft ambiguity

The DISCONNECT prose sections **3.13.3–3.13.6** order the fields as Packet
Identifier, Reason Code, Session Expiry Interval, Reason String. Its diagram
lists expiry before reason. This plugin follows the prose, matching the existing
client codecs. The independent DISCONNECT fixture asserts that choice. Review
this discrepancy when moving to a later draft; do not silently support both
orders, since both can look syntactically valid.

## Tests and maintenance

```sh
python3 -m unittest discover -s wireshark/tests -v
```

Tests require `tshark` with Lua enabled and Python 3.10 or later. No Python test
packages are required. A missing executable fails the run rather than skipping
verification. `TSHARK` can select an alternative executable.

Tests write deterministic Ethernet/IPv4/UDP PCAPs without live capture or capture
privileges, then assert actual tshark fields and expert warnings. Hand-authored
wire fixtures cite the pinned specification sections and are independent of the
client codecs. An additional test decodes a Python-client-generated CONNECT.
Coverage includes all 128 CONNECT flag combinations, standard protection schemes,
malformed fields, every incomplete prefix of the packet catalog, redissection,
port preferences, Decode As, coexistence with the built-in 1.2 dissector, and
600 deterministic random datagrams. Example captures contain synthetic data only.

Regenerate the committed sample capture after intentionally changing fixtures:

```sh
python3 wireshark/tests/generate_captures.py
```

The GitHub Actions conformance workflow runs the plugin suite on Ubuntu 24.04
and Debian trixie package builds of tshark. The job prints the actual Wireshark
and Lua versions. Local verification used Wireshark 4.2.2 / Lua 5.2.4; newer
matrix results are recorded by CI. The plugin avoids Lua 5.3-only bit operators
so it can run on Wireshark's Lua 5.2 and 5.3/5.4 runtimes.

When the draft changes, follow SPECIFICATION.md: review the wire-format delta,
update the affected dissector handlers and independent fixtures together,
regenerate the capture, and run the version matrix. No client release is needed
just to install a revised Lua file.
