"""MQTT-SN 2.0 CSD01 §3.6.1 and §3.20 conformance tests.

Covers MQTT-SN-3.6.1.2-1/-2, MQTT-SN-3.6.1.2.1-1,
MQTT-SN-3.6.1.4-1/-2 and MQTT-SN-3.6.1.6-1.
"""

import pytest

from mqttsn2 import (
    AdvertisePacket,
    GwInfoPacket,
    MqttSnError,
    PubWosPacket,
    SearchGwPacket,
    TopicRef,
    decode_advertise,
    decode_gwinfo,
    decode_packet,
    decode_pubwos,
    decode_searchgw,
    encode_advertise,
    encode_gwinfo,
    encode_pubwos,
    encode_searchgw,
)


def test_pubwos_topic_name_wire_shape() -> None:
    encoded = encode_pubwos(PubWosPacket(False, TopicRef.topic_name("a/b"), b"x"))
    assert encoded == bytes.fromhex("0912030003612f6278")
    decoded = decode_pubwos(decode_packet(encoded))
    assert decoded.topic.name == "a/b"
    assert decoded.payload == b"x"


def test_pubwos_rejects_session_alias() -> None:
    with pytest.raises(ValueError):
        PubWosPacket(False, TopicRef.session_alias(1), b"")


def test_advertise_round_trip() -> None:
    encoded = encode_advertise(AdvertisePacket(7, 60))
    assert encoded == bytes.fromhex("051607003c")
    assert decode_advertise(decode_packet(encoded)) == AdvertisePacket(7, 60)


def test_searchgw_opaque_network_information() -> None:
    encoded = encode_searchgw(SearchGwPacket(b"\x01\x02"))
    assert encoded == bytes.fromhex("04170102")
    assert decode_searchgw(decode_packet(encoded)).additional_network_information == b"\x01\x02"


def test_gwinfo_optional_address() -> None:
    encoded = encode_gwinfo(GwInfoPacket(7, bytes.fromhex("c0a80101")))
    assert encoded == bytes.fromhex("071807c0a80101")
    decoded = decode_gwinfo(decode_packet(encoded))
    assert decoded.gateway_identifier == 7
    assert decoded.gateway_address == bytes.fromhex("c0a80101")


def test_pubwos_reserved_flags_rejected() -> None:
    with pytest.raises(MqttSnError):
        decode_pubwos(decode_packet(bytes.fromhex("0512200001")))
