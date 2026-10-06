import pytest

from mqttsn2 import Client, MqttSnError, PacketType, decode_packet, encode_packet


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
