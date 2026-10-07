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

from mqttsn2 import (
    DisconnectOptions,
    MqttSnError,
    decode_disconnect,
    decode_packet,
    encode_disconnect,
)


def test_disconnect_round_trip_all_optional_fields() -> None:
    encoded = encode_disconnect(
        DisconnectOptions(0x1234, 0x82, 3600, "protocol error")
    )
    decoded = decode_disconnect(decode_packet(encoded))

    assert decoded.packet_identifier == 0x1234
    assert decoded.reason_code == 0x82
    assert decoded.session_expiry_interval == 3600
    assert decoded.reason_string == "protocol error"


def test_minimal_disconnect() -> None:
    assert encode_disconnect(DisconnectOptions()) == bytes.fromhex("030e00")


@pytest.mark.parametrize("packet", ["030e80", "050e010000"])
def test_disconnect_rejects_malformed_fields(packet: str) -> None:
    with pytest.raises(MqttSnError):
        decode_disconnect(decode_packet(bytes.fromhex(packet)))
