from dataclasses import dataclass
from enum import IntEnum

MAX_PACKET_SIZE = 65_535


class MqttSnError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PacketType(IntEnum):
    CONNECT = 0x01
    CONNACK = 0x02
    PUBLISH = 0x03
    PUBACK = 0x04
    PUBREC = 0x05
    PUBREL = 0x06
    PUBCOMP = 0x07
    SUBSCRIBE = 0x08
    SUBACK = 0x09
    UNSUBSCRIBE = 0x0A
    UNSUBACK = 0x0B
    PINGREQ = 0x0C
    PINGRESP = 0x0D
    DISCONNECT = 0x0E
    AUTH = 0x0F
    REGISTER = 0x10
    REGACK = 0x11
    PUBWOS = 0x12
    SLEEPREQ = 0x13
    SLEEPRESP = 0x14
    WAKEUP = 0x15
    ADVERTISE = 0x16
    SEARCHGW = 0x17
    GWINFO = 0x18
    FORWARDER_ENCAPSULATION = 0xFC
    CONNECTION_ENCAPSULATION = 0xFE
    PROTECTION_ENCAPSULATION = 0xFF




@dataclass(frozen=True)
class ConnectOptions:
    clean_start: bool
    allow_network_address_changes: bool
    allow_server_suggested_values: bool
    packet_identifier: int
    keep_alive_seconds: int
    maximum_packet_size: int = 0
    client_identifier: str = ""

    def __post_init__(self) -> None:
        if not 1 <= self.packet_identifier <= 0xFFFF:
            raise ValueError("packet_identifier must be 1..65535")
        if not 1 <= self.keep_alive_seconds <= 0xFFFF:
            raise ValueError("keep_alive_seconds must be 1..65535")
        if not (
            self.maximum_packet_size == 0
            or 10 <= self.maximum_packet_size <= 0xFFFF
        ):
            raise ValueError("maximum_packet_size must be 0 or 10..65535")
        _encode_utf8(self.client_identifier)


@dataclass(frozen=True)
class ConnAck:
    session_present: bool
    packet_identifier: int
    reason_code: int
    session_expiry_interval: int | None
    server_keep_alive: int | None
    authentication_method: str | None
    authentication_data: bytes | None
    assigned_client_identifier: str


def _encode_utf8(value: str) -> bytes:
    if "\x00" in value:
        raise MqttSnError("MALFORMED_PACKET", "MQTT-SN UTF-8 must not contain U+0000")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise MqttSnError("MALFORMED_PACKET", "Invalid MQTT-SN UTF-8 string") from exc


def _decode_utf8(value: memoryview) -> str:
    try:
        decoded = bytes(value).decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise MqttSnError("MALFORMED_PACKET", "Invalid MQTT-SN UTF-8 bytes") from exc
    _encode_utf8(decoded)
    return decoded


@dataclass(frozen=True)
class DecodedPacket:
    type: PacketType
    body: memoryview
    packet_length: int
    header_length: int


def _packet_type(value: int) -> PacketType:
    try:
        return PacketType(value)
    except ValueError as exc:
        raise MqttSnError(
            "RESERVED_TYPE", f"Reserved MQTT-SN packet type: 0x{value:02X}"
        ) from exc


def decode_packet(data: bytes | bytearray | memoryview) -> DecodedPacket:
    """Decode one packet using MQTT-SN 2.0 CSD01 framing."""
    source = memoryview(data).cast("B")
    if len(source) < 1:
        raise MqttSnError("NEED_MORE", "Length byte is incomplete")

    first_length = source[0]
    if first_length == 0x01:
        if len(source) < 4:
            raise MqttSnError("NEED_MORE", "Extended MQTT-SN header is incomplete")
        packet_length = (source[1] << 8) | source[2]
        header_length = 4
        type_offset = 3
        if packet_length < header_length:
            raise MqttSnError(
                "MALFORMED_PACKET",
                "Extended packet length is smaller than its header",
            )
    else:
        packet_length = first_length
        header_length = 2
        type_offset = 1
        if packet_length < header_length:
            raise MqttSnError(
                "MALFORMED_PACKET", "Packet length is smaller than its header"
            )

    if len(source) < packet_length:
        raise MqttSnError("NEED_MORE", "MQTT-SN packet is incomplete")

    packet_type = _packet_type(source[type_offset])
    return DecodedPacket(
        packet_type,
        source[header_length:packet_length],
        packet_length,
        header_length,
    )


def encode_packet(
    packet_type: PacketType, body: bytes | bytearray | memoryview = b""
) -> bytes:
    packet_body = memoryview(body).cast("B")
    header_length = 2 if len(packet_body) <= 253 else 4
    packet_length = len(packet_body) + header_length
    if packet_length > MAX_PACKET_SIZE:
        raise MqttSnError(
            "MALFORMED_PACKET", "MQTT-SN packet exceeds 65535 bytes"
        )

    output = bytearray(packet_length)
    if header_length == 2:
        output[0] = packet_length
        output[1] = int(packet_type)
    else:
        output[0] = 0x01
        output[1] = (packet_length >> 8) & 0xFF
        output[2] = packet_length & 0xFF
        output[3] = int(packet_type)

    output[header_length:] = packet_body
    return bytes(output)


def encode_connect(options: ConnectOptions) -> bytes:
    client_identifier = _encode_utf8(options.client_identifier)
    flags = 0
    if options.clean_start:
        flags |= 0x01
    if options.allow_network_address_changes:
        flags |= 0x20
    if options.allow_server_suggested_values:
        flags |= 0x40

    body = bytearray(8 + len(client_identifier))
    body[0] = flags
    body[1:3] = options.packet_identifier.to_bytes(2, "big")
    body[3] = 0x02
    body[4:6] = options.keep_alive_seconds.to_bytes(2, "big")
    body[6:8] = options.maximum_packet_size.to_bytes(2, "big")
    body[8:] = client_identifier
    return encode_packet(PacketType.CONNECT, body)


def decode_connack(packet: DecodedPacket) -> ConnAck:
    if packet.type is not PacketType.CONNACK:
        raise MqttSnError("MALFORMED_PACKET", "Expected CONNACK")

    body = packet.body
    if len(body) < 4:
        raise MqttSnError("MALFORMED_PACKET", "CONNACK is too short")

    flags = body[0]
    if flags & 0xF0:
        raise MqttSnError(
            "MALFORMED_PACKET", "CONNACK reserved flags are non-zero"
        )

    session_present = bool(flags & 0x01)
    packet_identifier = int.from_bytes(body[1:3], "big")
    if packet_identifier == 0:
        raise MqttSnError("MALFORMED_PACKET", "CONNACK Packet Identifier must be non-zero")
    reason_code = body[3]
    if session_present and reason_code != 0:
        raise MqttSnError(
            "MALFORMED_PACKET",
            "CONNACK Session Present must be zero on failure",
        )

    offset = 4
    session_expiry: int | None = None
    if flags & 0x02:
        if len(body) - offset < 4:
            raise MqttSnError(
                "MALFORMED_PACKET", "CONNACK Session Expiry Interval is truncated"
            )
        session_expiry = int.from_bytes(body[offset : offset + 4], "big")
        offset += 4

    server_keep_alive: int | None = None
    if flags & 0x04:
        if len(body) - offset < 2:
            raise MqttSnError(
                "MALFORMED_PACKET", "CONNACK Server Keep Alive is truncated"
            )
        server_keep_alive = int.from_bytes(body[offset : offset + 2], "big")
        if server_keep_alive == 0:
            raise MqttSnError(
                "MALFORMED_PACKET",
                "CONNACK Server Keep Alive must be greater than zero",
            )
        offset += 2

    authentication_method: str | None = None
    authentication_data: bytes | None = None
    if flags & 0x08:
        if len(body) - offset < 1:
            raise MqttSnError(
                "MALFORMED_PACKET",
                "CONNACK Authentication Method Length is truncated",
            )
        method_length = body[offset]
        offset += 1
        if len(body) - offset < method_length + 2:
            raise MqttSnError(
                "MALFORMED_PACKET", "CONNACK Authentication Method is truncated"
            )
        authentication_method = _decode_utf8(body[offset : offset + method_length])
        offset += method_length

        data_length = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        if len(body) - offset < data_length:
            raise MqttSnError(
                "MALFORMED_PACKET", "CONNACK Authentication Data is truncated"
            )
        authentication_data = bytes(body[offset : offset + data_length])
        offset += data_length

    assigned_client_identifier = _decode_utf8(body[offset:]) if offset < len(body) else ""

    return ConnAck(
        session_present,
        packet_identifier,
        reason_code,
        session_expiry,
        server_keep_alive,
        authentication_method,
        authentication_data,
        assigned_client_identifier,
    )
