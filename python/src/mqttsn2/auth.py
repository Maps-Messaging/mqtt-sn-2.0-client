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

from typing import Protocol

from .codec import ConnAck, MqttSnError
from .packets import AuthPacket

AUTH_SUCCESS = 0x00
AUTH_CONTINUE = 0x18
AUTH_REAUTHENTICATE = 0x19


class AuthenticationMechanism(Protocol):
    @property
    def method(self) -> str: ...

    def initial_response(self) -> bytes: ...

    def evaluate_challenge(self, challenge: bytes) -> bytes: ...

    @property
    def complete(self) -> bool: ...

    def reset(self) -> None: ...


class AuthenticationExchange:
    """Mechanism-agnostic MQTT-SN enhanced-authentication exchange."""

    def __init__(self, mechanism: AuthenticationMechanism) -> None:
        if not mechanism.method:
            raise ValueError("authentication method is required")
        encoded = mechanism.method.encode("utf-8")
        if not 1 <= len(encoded) <= 0xFF:
            raise ValueError("authentication method must contain 1..255 UTF-8 bytes")
        self.mechanism = mechanism
        self.active = False

    @property
    def method(self) -> str:
        return self.mechanism.method

    def initial_response(self) -> bytes:
        self.active = True
        return bytes(self.mechanism.initial_response())

    def continue_authentication(
        self,
        server_auth: AuthPacket,
        response_packet_identifier: int,
    ) -> AuthPacket:
        if not self.active:
            raise MqttSnError("STATE_ERROR", "Authentication exchange is not active")
        if server_auth.reason_code != AUTH_CONTINUE:
            raise MqttSnError(
                "STATE_ERROR",
                "Server AUTH must use reason code 0x18 during authentication continuation",
            )
        if server_auth.authentication_method != self.method:
            raise MqttSnError(
                "STATE_ERROR",
                "Authentication Method changed during exchange",
            )

        response = self.mechanism.evaluate_challenge(
            server_auth.authentication_data
        )
        return AuthPacket(
            response_packet_identifier,
            AUTH_CONTINUE,
            self.method,
            bytes(response),
        )

    def accept_connack(self, connack: ConnAck) -> None:
        if not self.active:
            return

        if connack.reason_code == AUTH_SUCCESS:
            if connack.authentication_method != self.method:
                raise MqttSnError(
                    "STATE_ERROR",
                    "Successful CONNACK must retain the Authentication Method",
                )
            if connack.authentication_data:
                self.mechanism.evaluate_challenge(connack.authentication_data)
            if not self.mechanism.complete:
                raise MqttSnError(
                    "STATE_ERROR",
                    "Authentication mechanism did not complete before successful CONNACK",
                )

        self.active = False

    def begin_reauthentication(self, packet_identifier: int) -> AuthPacket:
        if self.active:
            raise MqttSnError("STATE_ERROR", "Authentication exchange is already active")
        self.mechanism.reset()
        self.active = True
        return AuthPacket(
            packet_identifier,
            AUTH_REAUTHENTICATE,
            self.method,
            bytes(self.mechanism.initial_response()),
        )

    def reset(self) -> None:
        self.mechanism.reset()
        self.active = False
