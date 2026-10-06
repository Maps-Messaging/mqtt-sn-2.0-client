from collections.abc import Callable

from .codec import DecodedPacket, MqttSnError, PacketType, decode_packet, encode_packet


class Client:
    """Transport-neutral MQTT-SN client facade.

    The caller owns all network, radio, or serial I/O. accept() processes
    complete packets and returns the number of input bytes consumed. An
    incomplete trailing packet is left for the caller to retain and prepend
    to the next transport read.
    """

    def accept(
        self,
        data: bytes | bytearray | memoryview,
        handler: Callable[[DecodedPacket], None],
    ) -> int:
        source = memoryview(data).cast("B")
        consumed = 0

        while consumed < len(source):
            try:
                packet = decode_packet(source[consumed:])
            except MqttSnError as exc:
                if exc.code == "NEED_MORE":
                    return consumed
                raise

            handler(packet)
            consumed += packet.packet_length

        return consumed

    @staticmethod
    def encode(
        packet_type: PacketType, body: bytes | bytearray | memoryview = b""
    ) -> bytes:
        return encode_packet(packet_type, body)
