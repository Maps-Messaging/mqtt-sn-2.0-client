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
