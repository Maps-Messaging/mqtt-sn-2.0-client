import pytest

from mqttsn2 import (
    Client,
    ConnectOptions,
    MqttSnError,
    PacketType,
    PublishOptions,
    QoS,
    SleepRequest,
    SubscribeOptions,
    TopicRef,
    decode_ack,
    decode_connack,
    decode_packet,
    decode_pingresp,
    decode_publish,
    decode_sleepresp,
    decode_suback,
    encode_ack,
    encode_connect,
    encode_packet,
    encode_publish,
    encode_subscribe,
    encode_wakeup,
)


def test_packet_type_catalogue_and_reserved_values() -> None:
    for packet_type in PacketType:
        encoded = encode_packet(packet_type)
        assert decode_packet(encoded).type is packet_type

    for value in (0x00, 0x19, 0x7F, 0xFB, 0xFD):
        with pytest.raises(MqttSnError) as error:
            decode_packet(bytes((2, value)))
        assert error.value.code == "RESERVED_TYPE"


def test_short_and_extended_length_boundaries() -> None:
    short_packet = encode_packet(PacketType.PUBLISH, bytes(253))
    assert len(short_packet) == 255
    assert short_packet[0] == 255
    assert decode_packet(short_packet).header_length == 2

    extended_packet = encode_packet(PacketType.PUBLISH, bytes(254))
    assert len(extended_packet) == 258
    assert extended_packet[:4] == bytes.fromhex("01010203")
    assert decode_packet(extended_packet).header_length == 4


def test_maximum_packet_size_and_overflow() -> None:
    maximum = encode_packet(PacketType.PUBLISH, bytes(65_531))
    assert len(maximum) == 65_535
    assert decode_packet(maximum).packet_length == 65_535

    with pytest.raises(MqttSnError) as error:
        encode_packet(PacketType.PUBLISH, bytes(65_532))
    assert error.value.code == "MALFORMED_PACKET"


@pytest.mark.parametrize(
    ("packet", "code"),
    [
        (b"\x00", "MALFORMED_PACKET"),
        (b"\x01", "NEED_MORE"),
        (b"\x01\x00", "NEED_MORE"),
        (b"\x01\x00\x04", "NEED_MORE"),
        (bytes.fromhex("0100030c"), "MALFORMED_PACKET"),
    ],
)
def test_malformed_and_truncated_headers(packet: bytes, code: str) -> None:
    with pytest.raises(MqttSnError) as error:
        decode_packet(packet)
    assert error.value.code == code


def test_client_accepts_multiple_packets_and_preserves_source() -> None:
    source = bytearray.fromhex("020c020d")
    seen = []

    consumed = Client().accept(source, seen.append)

    assert consumed == 4
    assert [packet.type for packet in seen] == [PacketType.PINGREQ, PacketType.PINGRESP]
    assert source == bytearray.fromhex("020c020d")


def test_client_propagates_protocol_errors() -> None:
    with pytest.raises(MqttSnError) as error:
        Client().accept(bytes.fromhex("02fd"), lambda packet: None)
    assert error.value.code == "RESERVED_TYPE"


def test_connect_boundaries_and_null_character() -> None:
    encode_connect(ConnectOptions(True, False, False, 1, 1, 0, ""))
    encode_connect(ConnectOptions(False, True, True, 0xFFFF, 0xFFFF, 0xFFFF, "client"))

    with pytest.raises(ValueError):
        ConnectOptions(True, False, False, 0, 60, 0, "client")
    with pytest.raises(ValueError):
        ConnectOptions(True, False, False, 1, 0, 0, "client")
    with pytest.raises(ValueError):
        ConnectOptions(True, False, False, 1, 60, 9, "client")
    with pytest.raises(MqttSnError):
        ConnectOptions(True, False, False, 1, 60, 0, "a\x00b")


def test_connack_authentication_assigned_identifier_and_invalid_zero_id() -> None:
    connack = decode_connack(
        decode_packet(bytes.fromhex("1202081234000370736b0002010269643432"))
    )

    assert connack.authentication_method == "psk"
    assert connack.authentication_data == b"\x01\x02"
    assert connack.assigned_client_identifier == "id42"

    with pytest.raises(MqttSnError) as error:
        decode_connack(decode_packet(bytes.fromhex("060200000000")))
    assert error.value.code == "MALFORMED_PACKET"


@pytest.mark.parametrize(
    "packet",
    [
        "0802020001000000",
        "0802040001000000",
        "0802080001000370",
    ],
)
def test_connack_rejects_truncated_optional_fields(packet: str) -> None:
    with pytest.raises(MqttSnError):
        decode_connack(decode_packet(bytes.fromhex(packet)))


def test_topic_alias_boundaries_and_wildcards() -> None:
    assert TopicRef.session_alias(1).alias == 1
    assert TopicRef.predefined_alias(0xFFFF).alias == 0xFFFF

    with pytest.raises(ValueError):
        TopicRef.session_alias(0)
    with pytest.raises(ValueError):
        TopicRef.predefined_alias(0x1_0000)
    with pytest.raises(MqttSnError):
        TopicRef.topic_name("sensors/+")
    with pytest.raises(MqttSnError):
        TopicRef.topic_filter("sensors/temp+")
    with pytest.raises(MqttSnError):
        TopicRef.topic_filter("sensors/#/x")


def test_publish_qos_one_qos_two_and_aliases() -> None:
    qos1 = PublishOptions(
        QoS.AT_LEAST_ONCE,
        False,
        True,
        0x1234,
        TopicRef.session_alias(42),
        b"\x01\x02",
    )
    decoded1 = decode_publish(decode_packet(encode_publish(qos1)))
    assert decoded1.qos is QoS.AT_LEAST_ONCE
    assert decoded1.packet_identifier == 0x1234
    assert decoded1.topic.alias == 42
    assert decoded1.retain

    qos2 = PublishOptions(
        QoS.EXACTLY_ONCE,
        True,
        False,
        0xFFFF,
        TopicRef.predefined_alias(7),
        b"",
    )
    decoded2 = decode_publish(decode_packet(encode_publish(qos2)))
    assert decoded2.qos is QoS.EXACTLY_ONCE
    assert decoded2.duplicate
    assert decoded2.topic.alias == 7


@pytest.mark.parametrize(
    "packet",
    [
        "060304000100",
        "0503000000",
        "07032000000001",
        "060303000361",
    ],
)
def test_publish_rejects_malformed_flags_aliases_and_truncation(packet: str) -> None:
    with pytest.raises(MqttSnError):
        decode_publish(decode_packet(bytes.fromhex(packet)))


def test_subscribe_option_bits_and_suback_validation() -> None:
    encoded = encode_subscribe(
        SubscribeOptions(
            0x1234,
            TopicRef.predefined_alias(9),
            2,
            True,
            QoS.EXACTLY_ONCE,
            True,
        )
    )
    assert encoded == bytes.fromhex("0708d912340009")

    for packet in (
        "0509000000",
        "0509800001",
        "07090400010000",
    ):
        with pytest.raises(MqttSnError):
            decode_suback(decode_packet(bytes.fromhex(packet)))


def test_acknowledgement_types_round_trip() -> None:
    for packet_type in (
        PacketType.PUBACK,
        PacketType.PUBREC,
        PacketType.PUBREL,
        PacketType.PUBCOMP,
        PacketType.UNSUBACK,
    ):
        decoded = decode_ack(
            decode_packet(encode_ack(packet_type, 0x1234, 0x80))
        )
        assert decoded.packet_identifier == 0x1234
        assert decoded.reason_code == 0x80

    with pytest.raises(ValueError):
        encode_ack(PacketType.PINGRESP, 1)


def test_ping_response_optional_remaining_count() -> None:
    without_count = decode_pingresp(decode_packet(bytes.fromhex("040d1234")))
    assert without_count.application_messages_remaining is None

    with_count = decode_pingresp(decode_packet(bytes.fromhex("050d1234ff")))
    assert with_count.application_messages_remaining == 255


@pytest.mark.parametrize(
    "packet",
    [
        "061402123400",
        "091401123400000000",
        "0b140112340000003c0001",
    ],
)
def test_sleep_response_rejects_invalid_flags_duration_and_trailing_bytes(packet: str) -> None:
    with pytest.raises(MqttSnError):
        decode_sleepresp(decode_packet(bytes.fromhex(packet)))


def test_sleep_request_boundaries_and_wakeup() -> None:
    SleepRequest(1, False, 1)
    SleepRequest(0xFFFF, True, 0xFFFF_FFFF)

    with pytest.raises(ValueError):
        SleepRequest(0, False, 1)
    with pytest.raises(ValueError):
        SleepRequest(1, False, 0)

    assert encode_wakeup() == bytes.fromhex("0215")
