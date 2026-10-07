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
