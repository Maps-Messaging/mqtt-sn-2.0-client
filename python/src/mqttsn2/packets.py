from dataclasses import dataclass
from enum import IntEnum

from .codec import DecodedPacket, MqttSnError, PacketType, decode_packet, encode_packet


class TopicType(IntEnum):
    SESSION_ALIAS = 0
    PREDEFINED_ALIAS = 1
    NAME = 3


class QoS(IntEnum):
    AT_MOST_ONCE = 0
    AT_LEAST_ONCE = 1
    EXACTLY_ONCE = 2


def _decode_utf8(value: bytes | bytearray | memoryview) -> str:
    try:
        result = bytes(value).decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise MqttSnError("MALFORMED_PACKET", "Invalid MQTT-SN UTF-8 bytes") from exc
    if "\x00" in result:
        raise MqttSnError("MALFORMED_PACKET", "MQTT-SN UTF-8 contains U+0000")
    return result


def _validate_topic_name(value: str) -> bytes:
    encoded = value.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > 0xFFFF:
        raise MqttSnError("MALFORMED_PACKET", "Topic Name length is invalid")
    if b"+" in encoded or b"#" in encoded:
        raise MqttSnError("MALFORMED_PACKET", "Topic Name contains a wildcard")
    if b"\x00" in encoded:
        raise MqttSnError("MALFORMED_PACKET", "Topic Name contains U+0000")
    return encoded


def _validate_topic_filter(value: str) -> bytes:
    encoded = value.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > 0xFFFF:
        raise MqttSnError("MALFORMED_PACKET", "Topic Filter length is invalid")
    if b"\x00" in encoded:
        raise MqttSnError("MALFORMED_PACKET", "Topic Filter contains U+0000")

    for index, char in enumerate(encoded):
        if char == ord("#"):
            if index != len(encoded) - 1 or (
                index != 0 and encoded[index - 1] != ord("/")
            ):
                raise MqttSnError(
                    "MALFORMED_PACKET",
                    "Multi-level wildcard must occupy the final level",
                )
        elif char == ord("+"):
            if (
                index != 0
                and encoded[index - 1] != ord("/")
                or index + 1 != len(encoded)
                and encoded[index + 1] != ord("/")
            ):
                raise MqttSnError(
                    "MALFORMED_PACKET",
                    "Single-level wildcard must occupy an entire level",
                )
    return encoded


@dataclass(frozen=True)
class TopicRef:
    type: TopicType
    alias: int = 0
    name: str = ""

    @staticmethod
    def topic_name(name: str) -> "TopicRef":
        _validate_topic_name(name)
        return TopicRef(TopicType.NAME, name=name)

    @staticmethod
    def topic_filter(topic_filter: str) -> "TopicRef":
        _validate_topic_filter(topic_filter)
        return TopicRef(TopicType.NAME, name=topic_filter)

    @staticmethod
    def session_alias(alias: int) -> "TopicRef":
        if not 1 <= alias <= 0xFFFF:
            raise ValueError("alias must be 1..65535")
        return TopicRef(TopicType.SESSION_ALIAS, alias=alias)

    @staticmethod
    def predefined_alias(alias: int) -> "TopicRef":
        if not 1 <= alias <= 0xFFFF:
            raise ValueError("alias must be 1..65535")
        return TopicRef(TopicType.PREDEFINED_ALIAS, alias=alias)


@dataclass(frozen=True)
class PublishOptions:
    qos: QoS
    duplicate: bool
    retain: bool
    packet_identifier: int
    topic: TopicRef
    payload: bytes = b""

    def __post_init__(self) -> None:
        if self.qos is QoS.AT_MOST_ONCE and self.packet_identifier != 0:
            raise ValueError("QoS 0 PUBLISH must not have a Packet Identifier")
        if self.qos is not QoS.AT_MOST_ONCE and not (
            1 <= self.packet_identifier <= 0xFFFF
        ):
            raise ValueError("QoS 1/2 Packet Identifier must be 1..65535")
        if self.duplicate and self.qos is not QoS.EXACTLY_ONCE:
            raise ValueError("DUP is only valid for QoS 2 in MQTT-SN 2.0")
        if self.topic.type is TopicType.NAME:
            _validate_topic_name(self.topic.name)


@dataclass(frozen=True)
class PublishPacket:
    qos: QoS
    duplicate: bool
    retain: bool
    packet_identifier: int
    topic: TopicRef
    payload: bytes


@dataclass(frozen=True)
class SubscribeOptions:
    packet_identifier: int
    topic: TopicRef
    retain_handling: int
    retain_as_published: bool
    maximum_qos: QoS
    no_local: bool

    def __post_init__(self) -> None:
        if not 1 <= self.packet_identifier <= 0xFFFF:
            raise ValueError("packet_identifier must be 1..65535")
        if not 0 <= self.retain_handling <= 2:
            raise ValueError("retain_handling must be 0..2")
        if self.topic.type is TopicType.NAME:
            _validate_topic_filter(self.topic.name)


@dataclass(frozen=True)
class SubAck:
    topic_type: TopicType
    topic_alias: int | None
    packet_identifier: int
    reason_code: int | None


@dataclass(frozen=True)
class Ack:
    packet_identifier: int
    reason_code: int | None


@dataclass(frozen=True)
class PingResp:
    packet_identifier: int
    application_messages_remaining: int | None




@dataclass(frozen=True)
class DisconnectOptions:
    packet_identifier: int | None = None
    reason_code: int | None = None
    session_expiry_interval: int | None = None
    reason_string: str = ""

    def __post_init__(self) -> None:
        if self.packet_identifier is not None and not 1 <= self.packet_identifier <= 0xFFFF:
            raise ValueError("packet_identifier must be 1..65535 when present")
        if self.reason_code is not None and not 0 <= self.reason_code <= 0xFF:
            raise ValueError("reason_code must be 0..255 when present")
        if self.session_expiry_interval is not None and not 0 <= self.session_expiry_interval <= 0xFFFF_FFFF:
            raise ValueError("session_expiry_interval must be 0..4294967295 when present")
        _decode_utf8(self.reason_string.encode("utf-8"))


@dataclass(frozen=True)
class DisconnectPacket:
    packet_identifier: int | None
    reason_code: int | None
    session_expiry_interval: int | None
    reason_string: str


@dataclass(frozen=True)
class SleepRequest:
    packet_identifier: int
    retain_topic_aliases: bool
    sleep_duration_seconds: int

    def __post_init__(self) -> None:
        if not 1 <= self.packet_identifier <= 0xFFFF:
            raise ValueError("packet_identifier must be 1..65535")
        if not 1 <= self.sleep_duration_seconds <= 0xFFFF_FFFF:
            raise ValueError("sleep_duration_seconds must be 1..4294967295")


@dataclass(frozen=True)
class SleepResponse:
    packet_identifier: int
    sleep_duration_seconds: int | None
    reason_code: int | None


def encode_register(packet_identifier: int, topic_name: str) -> bytes:
    if not 1 <= packet_identifier <= 0xFFFF:
        raise ValueError("packet_identifier must be 1..65535")
    topic = _validate_topic_name(topic_name)
    body = bytes([0]) + packet_identifier.to_bytes(2, "big") + topic
    return encode_packet(PacketType.REGISTER, body)


def encode_publish(options: PublishOptions) -> bytes:
    flags = int(options.topic.type)
    if options.retain:
        flags |= 0x10
    flags |= int(options.qos) << 5
    if options.duplicate:
        flags |= 0x80

    body = bytearray([flags])
    if options.qos is not QoS.AT_MOST_ONCE:
        body += options.packet_identifier.to_bytes(2, "big")

    if options.topic.type is TopicType.NAME:
        topic = _validate_topic_name(options.topic.name)
        body += len(topic).to_bytes(2, "big")
        body += topic
    else:
        if not 1 <= options.topic.alias <= 0xFFFF:
            raise ValueError("Topic Alias must be 1..65535")
        body += options.topic.alias.to_bytes(2, "big")

    body += options.payload
    return encode_packet(PacketType.PUBLISH, body)


def decode_publish(packet: DecodedPacket) -> PublishPacket:
    if packet.type is not PacketType.PUBLISH:
        raise MqttSnError("MALFORMED_PACKET", "Expected PUBLISH")
    body = packet.body
    if len(body) < 3:
        raise MqttSnError("MALFORMED_PACKET", "PUBLISH is too short")

    flags = body[0]
    if flags & 0x0C:
        raise MqttSnError("MALFORMED_PACKET", "PUBLISH reserved flags are non-zero")

    topic_value = flags & 0x03
    qos_value = (flags >> 5) & 0x03
    try:
        topic_type = TopicType(topic_value)
        qos = QoS(qos_value)
    except ValueError as exc:
        raise MqttSnError("MALFORMED_PACKET", "Reserved PUBLISH flag value") from exc

    duplicate = bool(flags & 0x80)
    retain = bool(flags & 0x10)
    if duplicate and qos is not QoS.EXACTLY_ONCE:
        raise MqttSnError("MALFORMED_PACKET", "DUP is only valid for QoS 2")

    offset = 1
    packet_identifier = 0
    if qos is not QoS.AT_MOST_ONCE:
        if len(body) - offset < 2:
            raise MqttSnError("MALFORMED_PACKET", "PUBLISH Packet Identifier is truncated")
        packet_identifier = int.from_bytes(body[offset : offset + 2], "big")
        if packet_identifier == 0:
            raise MqttSnError("MALFORMED_PACKET", "Packet Identifier must be non-zero")
        offset += 2

    if len(body) - offset < 2:
        raise MqttSnError("MALFORMED_PACKET", "PUBLISH topic value is truncated")
    topic_value = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2

    if topic_type is TopicType.NAME:
        if len(body) - offset < topic_value:
            raise MqttSnError("MALFORMED_PACKET", "PUBLISH Topic Name is truncated")
        name = _decode_utf8(body[offset : offset + topic_value])
        _validate_topic_name(name)
        topic = TopicRef.topic_name(name)
        offset += topic_value
    else:
        if topic_value == 0:
            raise MqttSnError("MALFORMED_PACKET", "Topic Alias must be non-zero")
        topic = (
            TopicRef.session_alias(topic_value)
            if topic_type is TopicType.SESSION_ALIAS
            else TopicRef.predefined_alias(topic_value)
        )

    return PublishPacket(
        qos, duplicate, retain, packet_identifier, topic, bytes(body[offset:])
    )


def encode_subscribe(options: SubscribeOptions) -> bytes:
    flags = (
        int(options.topic.type)
        | (options.retain_handling << 2)
        | (int(options.maximum_qos) << 5)
    )
    if options.retain_as_published:
        flags |= 0x10
    if options.no_local:
        flags |= 0x80

    body = bytearray([flags])
    body += options.packet_identifier.to_bytes(2, "big")
    if options.topic.type is TopicType.NAME:
        body += _validate_topic_filter(options.topic.name)
    else:
        body += options.topic.alias.to_bytes(2, "big")
    return encode_packet(PacketType.SUBSCRIBE, body)


def decode_suback(packet: DecodedPacket) -> SubAck:
    if packet.type is not PacketType.SUBACK:
        raise MqttSnError("MALFORMED_PACKET", "Expected SUBACK")
    body = packet.body
    if len(body) < 3:
        raise MqttSnError("MALFORMED_PACKET", "SUBACK is too short")

    flags = body[0]
    if flags & 0xF8:
        raise MqttSnError("MALFORMED_PACKET", "SUBACK reserved flags are non-zero")
    try:
        topic_type = TopicType(flags & 0x03)
    except ValueError as exc:
        raise MqttSnError("MALFORMED_PACKET", "Reserved SUBACK Topic Type") from exc
    if topic_type is TopicType.NAME:
        raise MqttSnError("MALFORMED_PACKET", "SUBACK Topic Type must be an alias")

    packet_identifier = int.from_bytes(body[1:3], "big")
    if packet_identifier == 0:
        raise MqttSnError("MALFORMED_PACKET", "SUBACK Packet Identifier must be non-zero")
    offset = 3
    topic_alias: int | None = None
    if flags & 0x04:
        if len(body) - offset < 2:
            raise MqttSnError("MALFORMED_PACKET", "SUBACK Topic Alias is truncated")
        topic_alias = int.from_bytes(body[offset : offset + 2], "big")
        if topic_alias == 0:
            raise MqttSnError("MALFORMED_PACKET", "SUBACK Topic Alias must be non-zero")
        offset += 2

    if len(body) - offset > 1:
        raise MqttSnError("MALFORMED_PACKET", "SUBACK has unexpected trailing bytes")
    reason = body[offset] if offset < len(body) else None
    return SubAck(topic_type, topic_alias, packet_identifier, reason)


def encode_unsubscribe(packet_identifier: int, topic: TopicRef) -> bytes:
    if not 1 <= packet_identifier <= 0xFFFF:
        raise ValueError("packet_identifier must be 1..65535")
    body = bytearray([int(topic.type)])
    body += packet_identifier.to_bytes(2, "big")
    if topic.type is TopicType.NAME:
        body += _validate_topic_filter(topic.name)
    else:
        body += topic.alias.to_bytes(2, "big")
    return encode_packet(PacketType.UNSUBSCRIBE, body)


_ACK_TYPES = {
    PacketType.PUBACK,
    PacketType.PUBREC,
    PacketType.PUBREL,
    PacketType.PUBCOMP,
    PacketType.UNSUBACK,
}


def encode_ack(
    packet_type: PacketType, packet_identifier: int, reason_code: int | None = None
) -> bytes:
    if packet_type not in _ACK_TYPES:
        raise ValueError("Unsupported acknowledgement type")
    if not 1 <= packet_identifier <= 0xFFFF:
        raise ValueError("packet_identifier must be 1..65535")
    body = bytearray(packet_identifier.to_bytes(2, "big"))
    if reason_code is not None:
        body.append(reason_code & 0xFF)
    return encode_packet(packet_type, body)


def decode_ack(packet: DecodedPacket) -> Ack:
    if packet.type not in _ACK_TYPES or len(packet.body) not in (2, 3):
        raise MqttSnError("MALFORMED_PACKET", "Invalid acknowledgement packet")
    packet_identifier = int.from_bytes(packet.body[:2], "big")
    if packet_identifier == 0:
        raise MqttSnError("MALFORMED_PACKET", "Packet Identifier must be non-zero")
    reason = packet.body[2] if len(packet.body) == 3 else None
    return Ack(packet_identifier, reason)


def encode_pingreq(packet_identifier: int) -> bytes:
    if not 1 <= packet_identifier <= 0xFFFF:
        raise ValueError("packet_identifier must be 1..65535")
    return encode_packet(PacketType.PINGREQ, packet_identifier.to_bytes(2, "big"))


def decode_pingresp(packet: DecodedPacket) -> PingResp:
    if packet.type is not PacketType.PINGRESP or len(packet.body) not in (2, 3):
        raise MqttSnError("MALFORMED_PACKET", "Invalid PINGRESP packet")
    packet_identifier = int.from_bytes(packet.body[:2], "big")
    if packet_identifier == 0:
        raise MqttSnError("MALFORMED_PACKET", "Packet Identifier must be non-zero")
    remaining = packet.body[2] if len(packet.body) == 3 else None
    return PingResp(packet_identifier, remaining)


def encode_sleepreq(request: SleepRequest) -> bytes:
    body = bytearray([1 if request.retain_topic_aliases else 0])
    body += request.packet_identifier.to_bytes(2, "big")
    body += request.sleep_duration_seconds.to_bytes(4, "big")
    return encode_packet(PacketType.SLEEPREQ, body)


def decode_sleepresp(packet: DecodedPacket) -> SleepResponse:
    if packet.type is not PacketType.SLEEPRESP or len(packet.body) < 3:
        raise MqttSnError("MALFORMED_PACKET", "Invalid SLEEPRESP packet")
    body = packet.body
    flags = body[0]
    if flags & 0xFE:
        raise MqttSnError("MALFORMED_PACKET", "SLEEPRESP reserved flags are non-zero")
    packet_identifier = int.from_bytes(body[1:3], "big")
    if packet_identifier == 0:
        raise MqttSnError("MALFORMED_PACKET", "Packet Identifier must be non-zero")

    offset = 3
    duration: int | None = None
    if flags & 0x01:
        if len(body) - offset < 4:
            raise MqttSnError("MALFORMED_PACKET", "SLEEPRESP duration is truncated")
        duration = int.from_bytes(body[offset : offset + 4], "big")
        if duration == 0:
            raise MqttSnError("MALFORMED_PACKET", "Sleep Duration must be greater than zero")
        offset += 4

    if len(body) - offset > 1:
        raise MqttSnError("MALFORMED_PACKET", "SLEEPRESP has unexpected trailing bytes")
    reason = body[offset] if offset < len(body) else None
    return SleepResponse(packet_identifier, duration, reason)


def encode_wakeup() -> bytes:
    return encode_packet(PacketType.WAKEUP)


def encode_disconnect(options: DisconnectOptions) -> bytes:
    flags = 0
    body = bytearray([0])

    if options.packet_identifier is not None:
        flags |= 0x01
        body += options.packet_identifier.to_bytes(2, "big")
    if options.reason_code is not None:
        flags |= 0x04
        body.append(options.reason_code)
    if options.session_expiry_interval is not None:
        flags |= 0x02
        body += options.session_expiry_interval.to_bytes(4, "big")
    if options.reason_string:
        body += options.reason_string.encode("utf-8")

    body[0] = flags
    return encode_packet(PacketType.DISCONNECT, body)


def decode_disconnect(packet: DecodedPacket) -> DisconnectPacket:
    if packet.type is not PacketType.DISCONNECT or len(packet.body) < 1:
        raise MqttSnError("MALFORMED_PACKET", "Invalid DISCONNECT packet")

    body = packet.body
    flags = body[0]
    if flags & 0xF8:
        raise MqttSnError("MALFORMED_PACKET", "DISCONNECT reserved flags are non-zero")

    offset = 1
    packet_identifier: int | None = None
    reason_code: int | None = None
    session_expiry_interval: int | None = None

    if flags & 0x01:
        if len(body) - offset < 2:
            raise MqttSnError("MALFORMED_PACKET", "DISCONNECT Packet Identifier is truncated")
        packet_identifier = int.from_bytes(body[offset : offset + 2], "big")
        if packet_identifier == 0:
            raise MqttSnError("MALFORMED_PACKET", "DISCONNECT Packet Identifier must be non-zero")
        offset += 2

    if flags & 0x04:
        if len(body) - offset < 1:
            raise MqttSnError("MALFORMED_PACKET", "DISCONNECT Reason Code is truncated")
        reason_code = body[offset]
        offset += 1

    if flags & 0x02:
        if len(body) - offset < 4:
            raise MqttSnError("MALFORMED_PACKET", "DISCONNECT Session Expiry Interval is truncated")
        session_expiry_interval = int.from_bytes(body[offset : offset + 4], "big")
        offset += 4

    reason_string = _decode_utf8(body[offset:]) if offset < len(body) else ""
    return DisconnectPacket(
        packet_identifier, reason_code, session_expiry_interval, reason_string
    )


@dataclass(frozen=True)
class AuthPacket:
    packet_identifier: int
    reason_code: int
    authentication_method: str
    authentication_data: bytes = b""

    def __post_init__(self) -> None:
        if not 1 <= self.packet_identifier <= 0xFFFF:
            raise ValueError("packet_identifier must be 1..65535")
        if not 0 <= self.reason_code <= 0xFF:
            raise ValueError("reason_code must be 0..255")
        method = self.authentication_method.encode("utf-8")
        _decode_utf8(method)
        if len(method) > 0xFF:
            raise ValueError("authentication_method must be at most 255 UTF-8 bytes")


def encode_auth(auth: AuthPacket) -> bytes:
    method = auth.authentication_method.encode("utf-8")
    body = bytearray(auth.packet_identifier.to_bytes(2, "big"))
    body.append(auth.reason_code)
    body.append(len(method))
    body += method
    body += auth.authentication_data
    return encode_packet(PacketType.AUTH, body)


def decode_auth(packet: DecodedPacket) -> AuthPacket:
    if packet.type is not PacketType.AUTH or len(packet.body) < 4:
        raise MqttSnError("MALFORMED_PACKET", "Invalid AUTH packet")

    packet_identifier = int.from_bytes(packet.body[:2], "big")
    if packet_identifier == 0:
        raise MqttSnError("MALFORMED_PACKET", "AUTH Packet Identifier must be non-zero")

    reason_code = packet.body[2]
    method_length = packet.body[3]
    if len(packet.body) < 4 + method_length:
        raise MqttSnError("MALFORMED_PACKET", "AUTH Authentication Method is truncated")

    method = _decode_utf8(packet.body[4 : 4 + method_length])
    data = bytes(packet.body[4 + method_length :])
    return AuthPacket(packet_identifier, reason_code, method, data)


@dataclass(frozen=True)
class PubWosPacket:
    retain: bool
    topic: TopicRef
    payload: bytes = b""

    def __post_init__(self) -> None:
        if self.topic.type is TopicType.SESSION_ALIAS:
            raise ValueError("PUBWOS does not allow Session Topic Alias")
        if self.topic.type is TopicType.NAME:
            _validate_topic_name(self.topic.name)


@dataclass(frozen=True)
class AdvertisePacket:
    gateway_identifier: int
    duration_seconds: int

    def __post_init__(self) -> None:
        if not 0 <= self.gateway_identifier <= 0xFF:
            raise ValueError("gateway_identifier must be 0..255")
        if not 0 <= self.duration_seconds <= 0xFFFF:
            raise ValueError("duration_seconds must be 0..65535")


@dataclass(frozen=True)
class SearchGwPacket:
    additional_network_information: bytes = b""


@dataclass(frozen=True)
class GwInfoPacket:
    gateway_identifier: int
    gateway_address: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.gateway_identifier <= 0xFF:
            raise ValueError("gateway_identifier must be 0..255")


def encode_pubwos(packet: PubWosPacket) -> bytes:
    flags = int(packet.topic.type)
    if packet.retain:
        flags |= 0x10

    body = bytearray([flags])
    if packet.topic.type is TopicType.NAME:
        topic = _validate_topic_name(packet.topic.name)
        body += len(topic).to_bytes(2, "big")
        body += topic
    elif packet.topic.type is TopicType.PREDEFINED_ALIAS:
        if not 1 <= packet.topic.alias <= 0xFFFF:
            raise ValueError("Predefined Topic Alias must be 1..65535")
        body += packet.topic.alias.to_bytes(2, "big")
    else:
        raise ValueError("PUBWOS Topic Type must be Predefined Topic Alias or Topic Name")

    body += packet.payload
    return encode_packet(PacketType.PUBWOS, body)


def decode_pubwos(packet: DecodedPacket) -> PubWosPacket:
    if packet.type is not PacketType.PUBWOS or len(packet.body) < 3:
        raise MqttSnError("MALFORMED_PACKET", "Invalid PUBWOS packet")

    flags = packet.body[0]
    if flags & 0xEC:
        raise MqttSnError("MALFORMED_PACKET", "PUBWOS reserved flags are non-zero")

    try:
        topic_type = TopicType(flags & 0x03)
    except ValueError as exc:
        raise MqttSnError("MALFORMED_PACKET", "Reserved PUBWOS Topic Type") from exc

    if topic_type is TopicType.SESSION_ALIAS:
        raise MqttSnError(
            "MALFORMED_PACKET",
            "PUBWOS Topic Type must be Predefined Topic Alias or Topic Name",
        )

    topic_value = int.from_bytes(packet.body[1:3], "big")
    offset = 3

    if topic_type is TopicType.NAME:
        if topic_value == 0 or len(packet.body) - offset < topic_value:
            raise MqttSnError("MALFORMED_PACKET", "PUBWOS Topic Name is invalid")
        name = _decode_utf8(packet.body[offset : offset + topic_value])
        _validate_topic_name(name)
        topic = TopicRef.topic_name(name)
        offset += topic_value
    else:
        if topic_value == 0:
            raise MqttSnError("MALFORMED_PACKET", "PUBWOS Predefined Topic Alias must be non-zero")
        topic = TopicRef.predefined_alias(topic_value)

    return PubWosPacket(bool(flags & 0x10), topic, bytes(packet.body[offset:]))


def encode_advertise(packet: AdvertisePacket) -> bytes:
    return encode_packet(
        PacketType.ADVERTISE,
        bytes([packet.gateway_identifier]) + packet.duration_seconds.to_bytes(2, "big"),
    )


def decode_advertise(packet: DecodedPacket) -> AdvertisePacket:
    if packet.type is not PacketType.ADVERTISE or len(packet.body) != 3:
        raise MqttSnError("MALFORMED_PACKET", "Invalid ADVERTISE packet")
    return AdvertisePacket(packet.body[0], int.from_bytes(packet.body[1:3], "big"))


def encode_searchgw(packet: SearchGwPacket) -> bytes:
    return encode_packet(PacketType.SEARCHGW, packet.additional_network_information)


def decode_searchgw(packet: DecodedPacket) -> SearchGwPacket:
    if packet.type is not PacketType.SEARCHGW:
        raise MqttSnError("MALFORMED_PACKET", "Expected SEARCHGW")
    return SearchGwPacket(bytes(packet.body))


def encode_gwinfo(packet: GwInfoPacket) -> bytes:
    return encode_packet(
        PacketType.GWINFO,
        bytes([packet.gateway_identifier]) + packet.gateway_address,
    )


def decode_gwinfo(packet: DecodedPacket) -> GwInfoPacket:
    if packet.type is not PacketType.GWINFO or len(packet.body) < 1:
        raise MqttSnError("MALFORMED_PACKET", "Invalid GWINFO packet")
    return GwInfoPacket(packet.body[0], bytes(packet.body[1:]))


@dataclass(frozen=True)
class ConnectionEncapsulation:
    client_identifier: str
    mqttsn_packet: bytes

    def __post_init__(self) -> None:
        encoded = self.client_identifier.encode("utf-8")
        _decode_utf8(encoded)
        if len(encoded) > 0xFFFF:
            raise ValueError("client_identifier exceeds 65535 UTF-8 bytes")


@dataclass(frozen=True)
class ForwarderEncapsulation:
    client_addressing_information: bytes
    mqttsn_packet: bytes

    def __post_init__(self) -> None:
        if len(self.client_addressing_information) > 0xFF:
            raise ValueError("client_addressing_information exceeds 255 bytes")


def _validate_single_inner_packet(data: bytes, connection_restricted: bool) -> None:
    if not data:
        raise MqttSnError("MALFORMED_PACKET", "Encapsulation must contain one MQTT-SN packet")
    packet = decode_packet(data)
    if packet.packet_length != len(data):
        raise MqttSnError("MALFORMED_PACKET", "Encapsulation must contain exactly one MQTT-SN packet")
    if connection_restricted and packet.type not in {
        PacketType.PUBLISH,
        PacketType.SUBSCRIBE,
        PacketType.UNSUBSCRIBE,
        PacketType.REGISTER,
        PacketType.DISCONNECT,
        PacketType.SLEEPREQ,
        PacketType.PINGREQ,
    }:
        raise MqttSnError(
            "MALFORMED_PACKET",
            f"Connection Encapsulation is not allowed for {packet.type.name}",
        )


def encode_connection_encapsulation(encapsulation: ConnectionEncapsulation) -> bytes:
    client_id = encapsulation.client_identifier.encode("utf-8")
    _validate_single_inner_packet(encapsulation.mqttsn_packet, True)
    body = (
        len(client_id).to_bytes(2, "big")
        + client_id
        + encapsulation.mqttsn_packet
    )
    return encode_packet(PacketType.CONNECTION_ENCAPSULATION, body)


def decode_connection_encapsulation(packet: DecodedPacket) -> ConnectionEncapsulation:
    if packet.type is not PacketType.CONNECTION_ENCAPSULATION or len(packet.body) < 2:
        raise MqttSnError("MALFORMED_PACKET", "Invalid Connection Encapsulation")
    client_id_length = int.from_bytes(packet.body[:2], "big")
    if len(packet.body) < 2 + client_id_length:
        raise MqttSnError("MALFORMED_PACKET", "Connection Client Identifier is truncated")
    client_id = _decode_utf8(packet.body[2 : 2 + client_id_length])
    inner = bytes(packet.body[2 + client_id_length :])
    _validate_single_inner_packet(inner, True)
    return ConnectionEncapsulation(client_id, inner)


def encode_forwarder_encapsulation(encapsulation: ForwarderEncapsulation) -> bytes:
    _validate_single_inner_packet(encapsulation.mqttsn_packet, False)
    body = (
        bytes([len(encapsulation.client_addressing_information)])
        + encapsulation.client_addressing_information
        + encapsulation.mqttsn_packet
    )
    return encode_packet(PacketType.FORWARDER_ENCAPSULATION, body)


def decode_forwarder_encapsulation(packet: DecodedPacket) -> ForwarderEncapsulation:
    if packet.type is not PacketType.FORWARDER_ENCAPSULATION or len(packet.body) < 1:
        raise MqttSnError("MALFORMED_PACKET", "Invalid Forwarder Encapsulation")
    addressing_length = packet.body[0]
    if len(packet.body) < 1 + addressing_length:
        raise MqttSnError("MALFORMED_PACKET", "Forwarder addressing information is truncated")
    addressing = bytes(packet.body[1 : 1 + addressing_length])
    inner = bytes(packet.body[1 + addressing_length :])
    _validate_single_inner_packet(inner, False)
    return ForwarderEncapsulation(addressing, inner)
