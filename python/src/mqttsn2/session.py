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

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from .codec import DecodedPacket, MqttSnError, PacketType, decode_connack, decode_packet
from .packets import (
    QoS,
    decode_ack,
    decode_pingresp,
    decode_publish,
    decode_sleepresp,
    decode_suback,
)


class ClientState(Enum):
    NONE = auto()
    DISCONNECTED = auto()
    CONNECTING = auto()
    ACTIVE = auto()
    ASLEEP = auto()
    AWAKE = auto()


@dataclass(frozen=True)
class _RequestInfo:
    packet_identifier: int
    expected_response: PacketType


class Session:
    """Transport-neutral MQTT-SN client state and flow controller."""

    def __init__(self, initial_packet_identifier: int = 1) -> None:
        if not 0 <= initial_packet_identifier <= 0xFFFF:
            raise ValueError("initial_packet_identifier must be 0..65535")
        self.state = ClientState.NONE
        self._next_packet_identifier = initial_packet_identifier or 1
        self._connect_packet_identifier = 0

        self.outbound_request_type: PacketType | None = None
        self.expected_response_type: PacketType | None = None
        self.outbound_packet_identifier = 0
        self.qos2_pubrel_pending = False

        self.inbound_request_type: PacketType | None = None
        self.inbound_packet_identifier = 0

    @property
    def has_outbound_request(self) -> bool:
        return self.outbound_request_type is not None

    @property
    def has_inbound_request(self) -> bool:
        return self.inbound_request_type is not None

    def next_packet_identifier(self) -> int:
        result = self._next_packet_identifier or 1
        self._next_packet_identifier = 1 if result == 0xFFFF else result + 1
        if (
            self.has_outbound_request
            and self._next_packet_identifier == self.outbound_packet_identifier
        ):
            self._next_packet_identifier = (
                1 if self._next_packet_identifier == 0xFFFF
                else self._next_packet_identifier + 1
            )
        return result

    def can_send(self, packet_type: PacketType) -> bool:
        if self.state in (ClientState.NONE, ClientState.DISCONNECTED):
            return packet_type in {
                PacketType.CONNECT,
                PacketType.PUBWOS,
                PacketType.SEARCHGW,
                PacketType.GWINFO,
            }

        if self.state is ClientState.CONNECTING:
            return packet_type in {
                PacketType.AUTH,
                PacketType.DISCONNECT,
                PacketType.PUBWOS,
                PacketType.SEARCHGW,
                PacketType.GWINFO,
            }

        if self.state is ClientState.ASLEEP:
            return packet_type in {
                PacketType.PINGREQ,
                PacketType.CONNECT,
                PacketType.DISCONNECT,
            }

        if self.state is ClientState.AWAKE:
            return packet_type in {
                PacketType.PUBACK,
                PacketType.PUBREC,
                PacketType.PUBCOMP,
                PacketType.REGACK,
                PacketType.CONNECT,
                PacketType.DISCONNECT,
            }

        if self.state is ClientState.ACTIVE:
            return packet_type not in {
                PacketType.CONNACK,
                PacketType.SUBACK,
                PacketType.UNSUBACK,
                PacketType.PINGRESP,
                PacketType.SLEEPRESP,
                PacketType.ADVERTISE,
                PacketType.WAKEUP,
            }

        return False

    def track_outbound(self, packet_data: bytes | DecodedPacket) -> None:
        packet = self._single(packet_data)
        if not self.can_send(packet.type):
            raise MqttSnError(
                "STATE_ERROR",
                f"Packet {packet.type.name} is not valid in state {self.state.name}",
            )

        self._track_client_response(packet)

        if packet.type is PacketType.CONNECT:
            self._connect_packet_identifier = self._read_u16(
                packet.body, 1, "CONNECT Packet Identifier"
            )
            self._clear_flows()
            self.state = ClientState.CONNECTING
            return

        if packet.type is PacketType.DISCONNECT:
            self._clear_flows()
            self.state = ClientState.DISCONNECTED
            return

        request = self._outbound_request_info(packet)
        if request is None:
            return

        if self.has_outbound_request:
            if (
                packet.type is PacketType.PUBREL
                and self.outbound_request_type is PacketType.PUBLISH
                and self.qos2_pubrel_pending
                and request.packet_identifier == self.outbound_packet_identifier
            ):
                self.outbound_request_type = PacketType.PUBREL
                self.expected_response_type = PacketType.PUBCOMP
                self.qos2_pubrel_pending = False
                return

            if (
                packet.type is PacketType.AUTH
                or packet.type is not self.outbound_request_type
                or request.packet_identifier != self.outbound_packet_identifier
            ):
                raise MqttSnError(
                    "FLOW_CONTROL",
                    "An MQTT-SN request is already awaiting acknowledgement",
                )
            return

        self.outbound_request_type = packet.type
        self.expected_response_type = request.expected_response
        self.outbound_packet_identifier = request.packet_identifier
        self.qos2_pubrel_pending = False

        if packet.type is PacketType.AUTH:
            self._connect_packet_identifier = request.packet_identifier

        if packet.type is PacketType.PINGREQ and self.state is ClientState.ASLEEP:
            self.state = ClientState.AWAKE

    def track_inbound(self, packet_data: bytes | DecodedPacket) -> None:
        packet = self._single(packet_data)

        if packet.type is PacketType.CONNACK:
            if self.state is not ClientState.CONNECTING:
                raise MqttSnError("STATE_ERROR", "CONNACK received outside CONNECTING")
            connack = decode_connack(packet)
            if connack.packet_identifier != self._connect_packet_identifier:
                raise MqttSnError(
                    "STATE_ERROR",
                    "CONNACK Packet Identifier does not match CONNECT/AUTH",
                )
            self._clear_outbound()
            self.state = (
                ClientState.ACTIVE
                if connack.reason_code == 0
                else ClientState.DISCONNECTED
            )
            return

        if packet.type is PacketType.DISCONNECT:
            self._clear_flows()
            self.state = ClientState.DISCONNECTED
            return

        if (
            self.has_outbound_request
            and packet.type is self.expected_response_type
        ):
            packet_identifier = self._response_packet_identifier(packet)
            if packet_identifier != self.outbound_packet_identifier:
                raise MqttSnError(
                    "STATE_ERROR",
                    "Response Packet Identifier does not match outstanding request",
                )

            if (
                packet.type is PacketType.PUBREC
                and self.outbound_request_type is PacketType.PUBLISH
            ):
                self.qos2_pubrel_pending = True
                return

            if packet.type is PacketType.SLEEPRESP:
                response = decode_sleepresp(packet)
                if response.reason_code is None or response.reason_code < 0x80:
                    self.state = ClientState.ASLEEP
            elif (
                packet.type is PacketType.PINGRESP
                and self.state is ClientState.AWAKE
            ):
                self.state = ClientState.ASLEEP

            self._clear_outbound()
            return

        self._track_inbound_request(packet)

    def retry_exhausted(self) -> None:
        self._clear_flows()
        self.state = ClientState.DISCONNECTED

    def _single(self, packet_data: bytes | DecodedPacket) -> DecodedPacket:
        if isinstance(packet_data, DecodedPacket):
            return packet_data
        packet = decode_packet(packet_data)
        if packet.packet_length != len(packet_data):
            raise MqttSnError(
                "MALFORMED_PACKET",
                "Buffer must contain exactly one MQTT-SN packet",
            )
        return packet

    def _outbound_request_info(self, packet: DecodedPacket) -> _RequestInfo | None:
        if packet.type is PacketType.PUBLISH:
            publish = decode_publish(packet)
            if publish.qos is QoS.AT_MOST_ONCE:
                return None
            return _RequestInfo(
                publish.packet_identifier,
                PacketType.PUBACK
                if publish.qos is QoS.AT_LEAST_ONCE
                else PacketType.PUBREC,
            )

        if packet.type is PacketType.PUBREL:
            return _RequestInfo(
                self._read_u16(packet.body, 0, "PUBREL Packet Identifier"),
                PacketType.PUBCOMP,
            )

        offset_one = {
            PacketType.REGISTER: PacketType.REGACK,
            PacketType.SUBSCRIBE: PacketType.SUBACK,
            PacketType.UNSUBSCRIBE: PacketType.UNSUBACK,
            PacketType.SLEEPREQ: PacketType.SLEEPRESP,
        }
        if packet.type in offset_one:
            return _RequestInfo(
                self._read_u16(
                    packet.body, 1, f"{packet.type.name} Packet Identifier"
                ),
                offset_one[packet.type],
            )

        if packet.type in {PacketType.PINGREQ, PacketType.AUTH}:
            return _RequestInfo(
                self._read_u16(
                    packet.body, 0, f"{packet.type.name} Packet Identifier"
                ),
                PacketType.PINGRESP
                if packet.type is PacketType.PINGREQ
                else PacketType.AUTH,
            )

        return None

    def _track_client_response(self, packet: DecodedPacket) -> None:
        if not self.has_inbound_request:
            return

        if packet.type is PacketType.PUBACK:
            self._require_inbound_response(
                PacketType.PUBLISH, decode_ack(packet).packet_identifier
            )
            self._clear_inbound()
        elif packet.type is PacketType.PUBREC:
            self._require_inbound_response(
                PacketType.PUBLISH, decode_ack(packet).packet_identifier
            )
            self.inbound_request_type = PacketType.PUBREL
        elif packet.type is PacketType.PUBCOMP:
            self._require_inbound_response(
                PacketType.PUBREL, decode_ack(packet).packet_identifier
            )
            self._clear_inbound()
        elif packet.type is PacketType.REGACK:
            self._require_inbound_response(
                PacketType.REGISTER,
                self._read_u16(packet.body, 1, "REGACK Packet Identifier"),
            )
            self._clear_inbound()

    def _track_inbound_request(self, packet: DecodedPacket) -> None:
        if packet.type is PacketType.PUBLISH:
            publish = decode_publish(packet)
            if publish.qos is QoS.AT_MOST_ONCE:
                return
            packet_identifier = publish.packet_identifier
        elif packet.type is PacketType.REGISTER:
            packet_identifier = self._read_u16(
                packet.body, 1, "REGISTER Packet Identifier"
            )
        elif packet.type is PacketType.PUBREL:
            packet_identifier = self._read_u16(
                packet.body, 0, "PUBREL Packet Identifier"
            )
            if (
                self.inbound_request_type is not PacketType.PUBREL
                or packet_identifier != self.inbound_packet_identifier
            ):
                raise MqttSnError("STATE_ERROR", "Unexpected PUBREL")
            return
        else:
            return

        if self.has_inbound_request:
            if (
                self.inbound_request_type is packet.type
                and self.inbound_packet_identifier == packet_identifier
            ):
                return
            raise MqttSnError(
                "FLOW_CONTROL",
                "Server sent a second flow-controlled request before acknowledgement",
            )

        self.inbound_request_type = packet.type
        self.inbound_packet_identifier = packet_identifier

    def _response_packet_identifier(self, packet: DecodedPacket) -> int:
        if packet.type in {
            PacketType.PUBACK,
            PacketType.PUBREC,
            PacketType.PUBCOMP,
            PacketType.UNSUBACK,
        }:
            return decode_ack(packet).packet_identifier
        if packet.type is PacketType.SUBACK:
            return decode_suback(packet).packet_identifier
        if packet.type is PacketType.PINGRESP:
            return decode_pingresp(packet).packet_identifier
        if packet.type is PacketType.SLEEPRESP:
            return decode_sleepresp(packet).packet_identifier
        if packet.type is PacketType.REGACK:
            return self._read_u16(packet.body, 1, "REGACK Packet Identifier")
        if packet.type is PacketType.AUTH:
            return self._read_u16(packet.body, 0, "AUTH Packet Identifier")
        raise MqttSnError(
            "STATE_ERROR",
            f"Packet is not a response to a tracked request: {packet.type.name}",
        )

    def _require_inbound_response(
        self, request_type: PacketType, packet_identifier: int
    ) -> None:
        if (
            self.inbound_request_type is not request_type
            or packet_identifier != self.inbound_packet_identifier
        ):
            raise MqttSnError(
                "STATE_ERROR",
                f"Response does not match inbound {request_type.name} request",
            )

    @staticmethod
    def _read_u16(body: bytes | memoryview, offset: int, field: str) -> int:
        if offset < 0 or len(body) - offset < 2:
            raise MqttSnError("MALFORMED_PACKET", f"{field} is truncated")
        value = int.from_bytes(body[offset : offset + 2], "big")
        if value == 0:
            raise MqttSnError("MALFORMED_PACKET", f"{field} must be non-zero")
        return value

    def _clear_flows(self) -> None:
        self._clear_outbound()
        self._clear_inbound()

    def _clear_outbound(self) -> None:
        self.outbound_request_type = None
        self.expected_response_type = None
        self.outbound_packet_identifier = 0
        self.qos2_pubrel_pending = False

    def _clear_inbound(self) -> None:
        self.inbound_request_type = None
        self.inbound_packet_identifier = 0
