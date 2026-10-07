from dataclasses import dataclass
from enum import IntEnum

from .codec import DecodedPacket, MqttSnError, PacketType, encode_packet


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
