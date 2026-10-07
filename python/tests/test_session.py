"""MQTT-SN 2.0 CSD01 §4.9 flow control and §4.14 client-state tests."""

import pytest

from mqttsn2 import (
    ClientState,
    ConnectOptions,
    MqttSnError,
    PacketType,
    PublishOptions,
    QoS,
    Session,
    SleepRequest,
    SubscribeOptions,
    TopicRef,
    decode_packet,
    encode_ack,
    encode_connect,
    encode_pingreq,
    encode_publish,
    encode_sleepreq,
    encode_subscribe,
)


def active_session() -> Session:
    session = Session()
    session.track_outbound(
        encode_connect(
            ConnectOptions(True, False, False, 0x1001, 60, 0, "state-test")
        )
    )
    session.track_inbound(bytes.fromhex("060200100100"))
    return session


def test_connect_and_connack_transition_active() -> None:
    session = Session()
    session.track_outbound(
        encode_connect(
            ConnectOptions(True, False, False, 0x1001, 60, 0, "state-test")
        )
    )
    assert session.state is ClientState.CONNECTING
    session.track_inbound(bytes.fromhex("060200100100"))
    assert session.state is ClientState.ACTIVE


def test_one_outstanding_request_and_retransmission() -> None:
    session = active_session()
    subscribe = encode_subscribe(
        SubscribeOptions(
            0x2001,
            TopicRef.topic_filter("sensors/+"),
            0,
            False,
            QoS.AT_LEAST_ONCE,
            False,
        )
    )
    session.track_outbound(subscribe)
    session.track_outbound(subscribe)

    with pytest.raises(MqttSnError) as error:
        session.track_outbound(encode_pingreq(0x2002))
    assert error.value.code == "FLOW_CONTROL"


def test_mismatched_response_rejected() -> None:
    session = active_session()
    session.track_outbound(
        encode_subscribe(
            SubscribeOptions(
                0x2001,
                TopicRef.topic_filter("sensors/+"),
                0,
                False,
                QoS.AT_LEAST_ONCE,
                False,
            )
        )
    )

    with pytest.raises(MqttSnError) as error:
        session.track_inbound(bytes.fromhex("0509002002"))
    assert error.value.code == "STATE_ERROR"
    assert session.has_outbound_request


def test_qos_two_flow() -> None:
    session = active_session()
    session.track_outbound(
        encode_publish(
            PublishOptions(
                QoS.EXACTLY_ONCE,
                False,
                False,
                0x5001,
                TopicRef.topic_name("a/b"),
                b"",
            )
        )
    )
    session.track_inbound(encode_ack(PacketType.PUBREC, 0x5001))
    session.track_outbound(encode_ack(PacketType.PUBREL, 0x5001))
    session.track_inbound(encode_ack(PacketType.PUBCOMP, 0x5001))
    assert not session.has_outbound_request


def test_sleep_wake_ping_cycle() -> None:
    session = active_session()
    session.track_outbound(encode_sleepreq(SleepRequest(0x3001, True, 60)))
    session.track_inbound(bytes.fromhex("0a140130010000003c00"))
    assert session.state is ClientState.ASLEEP

    session.track_outbound(encode_pingreq(0x3002))
    assert session.state is ClientState.AWAKE
    session.track_inbound(bytes.fromhex("040d3002"))
    assert session.state is ClientState.ASLEEP


def test_inbound_flow_control_and_ack() -> None:
    session = active_session()
    first = encode_publish(
        PublishOptions(
            QoS.AT_LEAST_ONCE,
            False,
            False,
            0x4001,
            TopicRef.topic_name("a/b"),
            b"x",
        )
    )
    second = encode_publish(
        PublishOptions(
            QoS.AT_LEAST_ONCE,
            False,
            False,
            0x4002,
            TopicRef.topic_name("a/b"),
            b"y",
        )
    )

    session.track_inbound(first)
    with pytest.raises(MqttSnError) as error:
        session.track_inbound(second)
    assert error.value.code == "FLOW_CONTROL"

    session.track_outbound(encode_ack(PacketType.PUBACK, 0x4001))
    assert not session.has_inbound_request


def test_packet_identifier_wraps_and_retry_exhaustion_disconnects() -> None:
    session = Session(0xFFFF)
    assert session.next_packet_identifier() == 0xFFFF
    assert session.next_packet_identifier() == 1

    session = active_session()
    session.track_outbound(encode_pingreq(0x6001))
    session.retry_exhausted()
    assert session.state is ClientState.DISCONNECTED
    assert not session.has_outbound_request
