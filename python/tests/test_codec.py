import pytest

from mqttsn2 import (
    Client,
    ConnectOptions,
    MqttSnError,
    PacketType,
    decode_connack,
    decode_packet,
    encode_connect,
    encode_packet,
)


def test_short_pingreq_round_trip() -> None:
    encoded = encode_packet(PacketType.PINGREQ)

    assert encoded == bytes.fromhex("020c")

    decoded = decode_packet(encoded)
    assert decoded.type is PacketType.PINGREQ
    assert decoded.header_length == 2
    assert bytes(decoded.body) == b""


def test_three_byte_length_round_trip() -> None:
    body = bytes([0x42]) * 254
    encoded = encode_packet(PacketType.PUBLISH, body)

    assert len(encoded) == 258
    assert encoded[:4] == bytes.fromhex("01010203")

    decoded = decode_packet(encoded)
    assert decoded.header_length == 4
    assert bytes(decoded.body) == body


def test_reserved_type_is_rejected() -> None:
    with pytest.raises(MqttSnError) as error:
        decode_packet(bytes.fromhex("02fd"))

    assert error.value.code == "RESERVED_TYPE"


def test_partial_trailing_packet_is_not_consumed() -> None:
    packets = []

    consumed = Client().accept(bytes.fromhex("020c0101"), packets.append)

    assert consumed == 2
    assert [packet.type for packet in packets] == [PacketType.PINGREQ]


def test_strict_base_connect() -> None:
    encoded = encode_connect(
        ConnectOptions(
            clean_start=True,
            allow_network_address_changes=False,
            allow_server_suggested_values=False,
            packet_identifier=0x1234,
            keep_alive_seconds=60,
            maximum_packet_size=0,
            client_identifier="client1",
        )
    )

    assert encoded == bytes.fromhex(
        "110101123402003c0000636c69656e7431"
    )


def test_connack_with_suggested_values() -> None:
    packet = decode_packet(bytes.fromhex("0c020612340000000078003c"))

    connack = decode_connack(packet)

    assert connack.packet_identifier == 0x1234
    assert connack.reason_code == 0
    assert connack.session_expiry_interval == 120
    assert connack.server_keep_alive == 60


def test_connack_rejects_reserved_flags() -> None:
    packet = decode_packet(bytes.fromhex("060280000100"))

    with pytest.raises(MqttSnError) as error:
        decode_connack(packet)

    assert error.value.code == "MALFORMED_PACKET"


def test_mqttsn_utf8_rejects_null() -> None:
    with pytest.raises(MqttSnError):
        ConnectOptions(
            clean_start=True,
            allow_network_address_changes=False,
            allow_server_suggested_values=False,
            packet_identifier=1,
            keep_alive_seconds=60,
            client_identifier="a\x00b",
        )
