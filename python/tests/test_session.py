#
#  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
#
#  Licensed under the Apache License, Version 2.0 with the Commons Clause
#  (the "License"); you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
#
#      http://www.apache.org/licenses/LICENSE-2.0
#      https://commonsclause.com/
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

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


def test_repeated_sleep_request_and_retransmission_remain_asleep() -> None:
    session = active_session()
    session.track_outbound(encode_sleepreq(SleepRequest(0x3001, True, 60)))
    session.track_inbound(bytes.fromhex("061400300100"))
    assert session.state is ClientState.ASLEEP
    renewal = encode_sleepreq(SleepRequest(0x3002, False, 120))
    session.track_outbound(renewal)
    session.track_outbound(renewal)
    session.track_inbound(bytes.fromhex("061400300200"))
    assert session.state is ClientState.ASLEEP
    assert not session.has_outbound_request


def test_auth_renewal_pauses_traffic_and_completes_without_connack() -> None:
    from mqttsn2 import AuthPacket, encode_auth
    session = Session()
    session.track_outbound(encode_connect(ConnectOptions(True, False, False, 1, 60, 0, "auth", "TEST", b"")))
    session.track_inbound(bytes.fromhex("060200000100"))
    session.track_outbound(encode_auth(AuthPacket(2, 0x19, "TEST", b"")))
    assert not session.can_send(PacketType.PUBLISH)
    session.track_inbound(encode_auth(AuthPacket(2, 0x18, "TEST", b"challenge")))
    session.track_outbound(encode_auth(AuthPacket(3, 0x18, "TEST", b"response")))
    session.track_inbound(encode_auth(AuthPacket(3, 0, "TEST", b"final")))
    assert session.state is ClientState.ACTIVE
    assert session.can_send(PacketType.PUBLISH)
    assert not session.has_outbound_request


def test_auth_renewal_requires_negotiated_method() -> None:
    from mqttsn2 import AuthPacket, encode_auth
    session = active_session()
    with pytest.raises(MqttSnError):
        session.track_outbound(encode_auth(AuthPacket(2, 0x19, "TEST", b"")))


def test_sleep_renewal_honours_server_duration_and_rejection_keeps_old_duration() -> None:
    session = active_session()
    session.track_outbound(encode_sleepreq(SleepRequest(0x3001, True, 60)))
    session.track_inbound(bytes.fromhex("0a140130010000007800"))
    assert session.sleep_duration_seconds == 120
    session.track_outbound(encode_sleepreq(SleepRequest(0x3002, True, 300)))
    session.track_inbound(bytes.fromhex("061400300280"))
    assert session.sleep_duration_seconds == 120
    assert session.state is ClientState.ASLEEP


def test_renewal_rejects_changed_method_wrong_identifier_and_auth_retry() -> None:
    from mqttsn2 import AuthPacket, encode_auth
    session = Session()
    session.track_outbound(encode_connect(ConnectOptions(True, False, False, 1, 60, 0, "auth", "TEST", b"")))
    session.track_inbound(bytes.fromhex("060200000100"))
    with pytest.raises(MqttSnError):
        session.track_outbound(encode_auth(AuthPacket(2, 0x19, "OTHER", b"")))
    renewal = encode_auth(AuthPacket(2, 0x19, "TEST", b""))
    session.track_outbound(renewal)
    with pytest.raises(MqttSnError):
        session.track_outbound(renewal)
    with pytest.raises(MqttSnError):
        session.track_inbound(encode_auth(AuthPacket(3, 0, "TEST", b"")))
    session.track_inbound(encode_auth(AuthPacket(2, 0, "TEST", b"")))
    with pytest.raises(MqttSnError):
        session.track_inbound(encode_auth(AuthPacket(2, 0, "TEST", b"")))
