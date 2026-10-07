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

import pytest

from mqttsn2 import AuthPacket, MqttSnError, decode_auth, decode_packet, encode_auth


def test_auth_round_trip() -> None:
    encoded = encode_auth(AuthPacket(0x1234, 0x18, "psk", b"\x01\x02\x03"))
    decoded = decode_auth(decode_packet(encoded))

    assert decoded.packet_identifier == 0x1234
    assert decoded.reason_code == 0x18
    assert decoded.authentication_method == "psk"
    assert decoded.authentication_data == b"\x01\x02\x03"


@pytest.mark.parametrize("packet", ["060f00001800", "070f1234180370"])
def test_auth_rejects_malformed_fields(packet: str) -> None:
    with pytest.raises(MqttSnError):
        decode_auth(decode_packet(bytes.fromhex(packet)))
