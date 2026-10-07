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
    AUTH_CONTINUE,
    AUTH_REAUTHENTICATE,
    AuthenticationExchange,
    AuthPacket,
    ConnAck,
    ConnectOptions,
    MqttSnError,
    encode_connect,
)


class MechanismStub:
    method = "TEST"

    def __init__(self) -> None:
        self._complete = False
        self.reset_count = 0

    def initial_response(self) -> bytes:
        return b"\x01"

    def evaluate_challenge(self, challenge: bytes) -> bytes:
        if challenge == b"\x7f":
            self._complete = True
            return b""
        return b"\x02"

    @property
    def complete(self) -> bool:
        return self._complete

    def reset(self) -> None:
        self._complete = False
        self.reset_count += 1


def test_authenticated_connect_wire_shape() -> None:
    encoded = encode_connect(
        ConnectOptions(
            True,
            False,
            False,
            0x1234,
            60,
            0,
            "client1",
            "PLAIN",
            b"\x01\x02\x03",
        )
    )

    assert encoded == bytes.fromhex(
        "1c0105123402003c000005504c41494e0003010203636c69656e7431"
    )


def test_generic_authentication_exchange_and_reauthentication() -> None:
    mechanism = MechanismStub()
    exchange = AuthenticationExchange(mechanism)

    assert exchange.initial_response() == b"\x01"

    response = exchange.continue_authentication(
        AuthPacket(0x1001, AUTH_CONTINUE, "TEST", b"\x10"),
        0x1002,
    )
    assert response.reason_code == AUTH_CONTINUE
    assert response.authentication_data == b"\x02"

    exchange.accept_connack(
        ConnAck(
            False,
            0x1002,
            0,
            None,
            None,
            "TEST",
            b"\x7f",
            "",
        )
    )
    assert mechanism.complete
    assert not exchange.active

    reauth = exchange.begin_reauthentication(0x2222)
    assert reauth.reason_code == AUTH_REAUTHENTICATE
    assert reauth.authentication_method == "TEST"
    assert reauth.authentication_data == b"\x01"
    assert mechanism.reset_count == 1


def test_method_change_is_rejected() -> None:
    exchange = AuthenticationExchange(MechanismStub())
    exchange.initial_response()

    with pytest.raises(MqttSnError) as error:
        exchange.continue_authentication(
            AuthPacket(1, AUTH_CONTINUE, "OTHER", b""),
            2,
        )
    assert error.value.code == "STATE_ERROR"
