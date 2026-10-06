import pytest

from mqttsn2 import (
    MqttSnError,
    PacketType,
    PublishOptions,
    QoS,
    SleepRequest,
    SubscribeOptions,
    TopicRef,
    decode_packet,
    decode_pingresp,
    decode_publish,
    decode_sleepresp,
    decode_suback,
    encode_pingreq,
    encode_publish,
    encode_sleepreq,
    encode_subscribe,
)


def test_publish_topic_name_qos_zero() -> None:
    encoded = encode_publish(
        PublishOptions(
            QoS.AT_MOST_ONCE,
            False,
            False,
            0,
            TopicRef.topic_name("a/b"),
            b"x",
        )
    )

    assert encoded == bytes.fromhex("0903030003612f6278")

    decoded = decode_publish(decode_packet(encoded))
    assert decoded.qos is QoS.AT_MOST_ONCE
    assert decoded.topic.name == "a/b"
    assert decoded.payload == b"x"


def test_subscribe_and_suback() -> None:
    encoded = encode_subscribe(
        SubscribeOptions(
            0x1234,
            TopicRef.topic_filter("sensors/+"),
            0,
            False,
            QoS.AT_LEAST_ONCE,
            False,
        )
    )

    assert encoded[2] == 0x23
    assert encoded[3:5] == bytes.fromhex("1234")

    suback = decode_suback(
        decode_packet(bytes.fromhex("0809041234002a00"))
    )
    assert suback.packet_identifier == 0x1234
    assert suback.topic_alias == 42
    assert suback.reason_code == 0


def test_topic_wildcard_validation() -> None:
    with pytest.raises(MqttSnError):
        TopicRef.topic_name("sensors/+")
    with pytest.raises(MqttSnError):
        TopicRef.topic_filter("sensors/temp+")
    with pytest.raises(MqttSnError):
        TopicRef.topic_filter("sensors/#/x")


def test_ping_and_sleep() -> None:
    assert encode_pingreq(0x1234) == bytes.fromhex("040c1234")

    pingresp = decode_pingresp(
        decode_packet(bytes.fromhex("050d123407"))
    )
    assert pingresp.application_messages_remaining == 7

    assert encode_sleepreq(
        SleepRequest(0x1234, True, 60)
    ) == bytes.fromhex("09130112340000003c")

    sleepresp = decode_sleepresp(
        decode_packet(bytes.fromhex("0a140112340000003c00"))
    )
    assert sleepresp.sleep_duration_seconds == 60
    assert sleepresp.reason_code == 0


def test_qos_zero_rejects_packet_identifier() -> None:
    with pytest.raises(ValueError):
        PublishOptions(
            QoS.AT_MOST_ONCE,
            False,
            False,
            1,
            TopicRef.topic_name("a/b"),
            b"",
        )
