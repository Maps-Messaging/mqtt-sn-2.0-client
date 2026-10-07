"""MQTT-SN 2.0 CSD01 §3.18 and §3.19 encapsulation conformance tests."""

import pytest

from mqttsn2 import (
    ConnectionEncapsulation,
    ForwarderEncapsulation,
    MqttSnError,
    decode_connection_encapsulation,
    decode_forwarder_encapsulation,
    decode_packet,
    encode_connection_encapsulation,
    encode_forwarder_encapsulation,
    encode_pingreq,
)


def test_connection_encapsulation_round_trip() -> None:
    inner = encode_pingreq(0x1234)
    encoded = encode_connection_encapsulation(
        ConnectionEncapsulation("client1", inner)
    )
    assert encoded == bytes.fromhex(
        "0ffe0007636c69656e7431040c1234"
    )
    decoded = decode_connection_encapsulation(decode_packet(encoded))
    assert decoded.client_identifier == "client1"
    assert decoded.mqttsn_packet == inner


def test_connection_encapsulation_rejects_server_packet() -> None:
    connack = bytes.fromhex("060200123400")
    with pytest.raises(MqttSnError):
        encode_connection_encapsulation(
            ConnectionEncapsulation("client1", connack)
        )


def test_connection_encapsulation_rejects_multiple_inner_packets() -> None:
    inner = bytes.fromhex("040c1234040c5678")
    with pytest.raises(MqttSnError):
        encode_connection_encapsulation(
            ConnectionEncapsulation("client1", inner)
        )


def test_forwarder_encapsulation_round_trip() -> None:
    inner = encode_pingreq(0x1234)
    encoded = encode_forwarder_encapsulation(
        ForwarderEncapsulation(b"\x01\x02", inner)
    )
    assert encoded == bytes.fromhex("09fc020102040c1234")
    decoded = decode_forwarder_encapsulation(decode_packet(encoded))
    assert decoded.client_addressing_information == b"\x01\x02"
    assert decoded.mqttsn_packet == inner


def test_forwarder_encapsulation_rejects_missing_inner_packet() -> None:
    with pytest.raises(MqttSnError):
        decode_forwarder_encapsulation(
            decode_packet(bytes.fromhex("04fc0155"))
        )
