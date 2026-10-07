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

"""MQTT-SN 2.0 CSD01 §3.17 Protection Encapsulation structural tests."""

import pytest

from mqttsn2 import (
    MqttSnError,
    ProtectedContent,
    ProtectionContext,
    ProtectionEnvelope,
    decode_protection,
    encode_forwarder_encapsulation,
    encode_pingreq,
    encode_protection,
    ForwarderEncapsulation,
)


class CopyProvider:
    def supports(self, scheme: int) -> bool:
        return scheme in (0x3C, 0x40)

    def authentication_only(self, scheme: int) -> bool:
        return scheme == 0x3C

    def authentication_tag_length(self, scheme: int, tag_length_code: int) -> int:
        if tag_length_code == 0:
            return 6
        if tag_length_code == 1:
            return 8 if scheme == 0x40 else 16
        if tag_length_code >= 4:
            return tag_length_code * 2
        return 0

    def protected_packet_length(self, scheme: int, mqttsn_packet_length: int) -> int:
        return mqttsn_packet_length

    def protect(
        self,
        context: ProtectionContext,
        mqttsn_packet: bytes,
    ) -> ProtectedContent:
        tag = bytes([len(context.authenticated_prefix) & 0xFF]) * (
            self.authentication_tag_length(context.scheme, context.tag_length_code)
        )
        return ProtectedContent(mqttsn_packet, tag)

    def unprotect(
        self,
        context: ProtectionContext,
        protected_packet: bytes,
        authentication_tag: bytes,
    ) -> bytes | None:
        expected = len(context.authenticated_prefix) & 0xFF
        if any(value != expected for value in authentication_tag):
            return None
        return protected_packet


def test_protection_round_trip() -> None:
    provider = CopyProvider()
    envelope = ProtectionEnvelope(
        0x3C,
        0x04,
        bytes.fromhex("0102030405060708"),
        bytes.fromhex("11121314"),
        bytes.fromhex("2122"),
        bytes.fromhex("0001"),
        encode_pingreq(0x1234),
    )

    encoded = encode_protection(envelope, provider)
    decoded = decode_protection(encoded, provider)

    assert decoded.scheme == 0x3C
    assert decoded.tag_length_code == 0x04
    assert decoded.sender_identifier == envelope.sender_identifier
    assert decoded.random == envelope.random
    assert decoded.cryptographic_material == envelope.cryptographic_material
    assert decoded.monotonic_counter == envelope.monotonic_counter
    assert decoded.mqttsn_packet == envelope.mqttsn_packet


def test_protection_rejects_tampered_tag() -> None:
    provider = CopyProvider()
    envelope = ProtectionEnvelope(
        0x3C, 0x04, bytes(8), bytes(4), b"", b"", encode_pingreq(1)
    )
    encoded = bytearray(encode_protection(envelope, provider))
    encoded[-1] ^= 1

    with pytest.raises(MqttSnError):
        decode_protection(bytes(encoded), provider)


def test_protection_rejects_forwarder_inner_packet() -> None:
    provider = CopyProvider()
    inner = encode_forwarder_encapsulation(
        ForwarderEncapsulation(b"\x01", encode_pingreq(1))
    )
    envelope = ProtectionEnvelope(
        0x3C, 0x04, bytes(8), bytes(4), b"", b"", inner
    )

    with pytest.raises(MqttSnError):
        encode_protection(envelope, provider)


def test_aead_requires_nominal_tag_code() -> None:
    provider = CopyProvider()
    envelope = ProtectionEnvelope(
        0x40, 0x04, bytes(8), bytes(4), b"", b"", encode_pingreq(1)
    )

    with pytest.raises(MqttSnError):
        encode_protection(envelope, provider)
