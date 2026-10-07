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

from dataclasses import dataclass
from typing import Protocol

from .codec import DecodedPacket, MqttSnError, PacketType, decode_packet, encode_packet


@dataclass(frozen=True)
class ProtectionContext:
    scheme: int
    tag_length_code: int
    sender_identifier: bytes
    random: bytes
    cryptographic_material: bytes
    monotonic_counter: bytes
    authenticated_prefix: bytes


@dataclass(frozen=True)
class ProtectedContent:
    protected_packet: bytes
    authentication_tag: bytes


class ProtectionProvider(Protocol):
    def supports(self, scheme: int) -> bool: ...

    def authentication_only(self, scheme: int) -> bool: ...

    def authentication_tag_length(self, scheme: int, tag_length_code: int) -> int: ...

    def protected_packet_length(self, scheme: int, mqttsn_packet_length: int) -> int: ...

    def protect(
        self,
        context: ProtectionContext,
        mqttsn_packet: bytes,
    ) -> ProtectedContent: ...

    def unprotect(
        self,
        context: ProtectionContext,
        protected_packet: bytes,
        authentication_tag: bytes,
    ) -> bytes | None: ...


@dataclass(frozen=True)
class ProtectionEnvelope:
    scheme: int
    tag_length_code: int
    sender_identifier: bytes
    random: bytes
    cryptographic_material: bytes
    monotonic_counter: bytes
    mqttsn_packet: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.scheme <= 0xFF:
            raise ValueError("scheme must be 0..255")
        if not 0 <= self.tag_length_code <= 0x0F:
            raise ValueError("tag_length_code must be 0..15")


def encode_protection(
    envelope: ProtectionEnvelope,
    provider: ProtectionProvider,
) -> bytes:
    _validate_envelope(envelope, provider)
    _validate_inner_packet(envelope.mqttsn_packet)

    counter_code = _counter_code(len(envelope.monotonic_counter))
    crypto_code = _crypto_code(len(envelope.cryptographic_material))
    tag_code = envelope.tag_length_code

    tag_length = provider.authentication_tag_length(envelope.scheme, tag_code)
    protected_length = provider.protected_packet_length(
        envelope.scheme, len(envelope.mqttsn_packet)
    )
    _validate_tag_rules(envelope.scheme, tag_code, tag_length, provider)
    if protected_length <= 0:
        raise MqttSnError("MALFORMED_PACKET", "Invalid protected packet length")

    body_length = (
        14
        + len(envelope.cryptographic_material)
        + len(envelope.monotonic_counter)
        + protected_length
        + tag_length
    )
    header_length = 2 if body_length <= 253 else 4
    packet_length = body_length + header_length
    if packet_length > 0xFFFF:
        raise MqttSnError("MALFORMED_PACKET", "Protection packet exceeds maximum size")

    prefix = bytearray()
    if header_length == 2:
        prefix.append(packet_length)
    else:
        prefix.append(0x01)
        prefix += packet_length.to_bytes(2, "big")
    prefix.append(int(PacketType.PROTECTION_ENCAPSULATION))

    flags = (tag_code << 4) | (crypto_code << 2) | counter_code
    prefix.append(flags)
    prefix.append(envelope.scheme)
    prefix += envelope.sender_identifier
    prefix += envelope.random
    prefix += envelope.cryptographic_material
    prefix += envelope.monotonic_counter

    context = ProtectionContext(
        envelope.scheme,
        tag_code,
        envelope.sender_identifier,
        envelope.random,
        envelope.cryptographic_material,
        envelope.monotonic_counter,
        bytes(prefix),
    )
    protected = provider.protect(context, envelope.mqttsn_packet)

    if len(protected.protected_packet) != protected_length:
        raise MqttSnError(
            "MALFORMED_PACKET",
            "Protection provider returned unexpected protected packet length",
        )
    if len(protected.authentication_tag) != tag_length:
        raise MqttSnError(
            "MALFORMED_PACKET",
            "Protection provider returned unexpected authentication tag length",
        )

    return bytes(prefix) + protected.protected_packet + protected.authentication_tag


def decode_protection(
    encoded: bytes,
    provider: ProtectionProvider,
) -> ProtectionEnvelope:
    outer = decode_packet(encoded)
    if (
        outer.packet_length != len(encoded)
        or outer.type is not PacketType.PROTECTION_ENCAPSULATION
    ):
        raise MqttSnError(
            "MALFORMED_PACKET",
            "Expected exactly one Protection Encapsulation packet",
        )

    body = outer.body
    if len(body) < 14:
        raise MqttSnError("MALFORMED_PACKET", "Protection fixed fields are truncated")

    flags = body[0]
    counter_code = flags & 0x03
    crypto_code = (flags >> 2) & 0x03
    tag_code = (flags >> 4) & 0x0F

    if counter_code == 0x03 or tag_code in (0x02, 0x03):
        raise MqttSnError("MALFORMED_PACKET", "Reserved protection length code")

    scheme = body[1]
    _validate_scheme(scheme, provider)

    offset = 2
    sender_identifier = bytes(body[offset : offset + 8])
    offset += 8
    random = bytes(body[offset : offset + 4])
    offset += 4

    crypto_length = _crypto_length(crypto_code)
    counter_length = _counter_length(counter_code)
    if len(body) - offset < crypto_length + counter_length:
        raise MqttSnError("MALFORMED_PACKET", "Protection optional material is truncated")

    cryptographic_material = bytes(body[offset : offset + crypto_length])
    offset += crypto_length
    monotonic_counter = bytes(body[offset : offset + counter_length])
    offset += counter_length

    tag_length = provider.authentication_tag_length(scheme, tag_code)
    _validate_tag_rules(scheme, tag_code, tag_length, provider)
    if tag_length <= 0 or len(body) - offset <= tag_length:
        raise MqttSnError("MALFORMED_PACKET", "Protected payload or tag is truncated")

    protected_length = len(body) - offset - tag_length
    protected_packet = bytes(body[offset : offset + protected_length])
    authentication_tag = bytes(body[offset + protected_length :])

    prefix_length = len(encoded) - protected_length - tag_length
    context = ProtectionContext(
        scheme,
        tag_code,
        sender_identifier,
        random,
        cryptographic_material,
        monotonic_counter,
        encoded[:prefix_length],
    )

    mqttsn_packet = provider.unprotect(
        context,
        protected_packet,
        authentication_tag,
    )
    if mqttsn_packet is None:
        raise MqttSnError("MALFORMED_PACKET", "Protection provider rejected authentication")

    _validate_inner_packet(mqttsn_packet)

    return ProtectionEnvelope(
        scheme,
        tag_code,
        sender_identifier,
        random,
        cryptographic_material,
        monotonic_counter,
        mqttsn_packet,
    )


def _validate_envelope(
    envelope: ProtectionEnvelope,
    provider: ProtectionProvider,
) -> None:
    _validate_scheme(envelope.scheme, provider)
    if len(envelope.sender_identifier) != 8:
        raise ValueError("sender_identifier must be exactly 8 bytes")
    if len(envelope.random) != 4:
        raise ValueError("random must be exactly 4 bytes")
    _counter_code(len(envelope.monotonic_counter))
    _crypto_code(len(envelope.cryptographic_material))
    if envelope.tag_length_code in (0x02, 0x03):
        raise MqttSnError("MALFORMED_PACKET", "Reserved authentication tag length code")


def _validate_scheme(scheme: int, provider: ProtectionProvider) -> None:
    if (0x05 <= scheme <= 0x3B) or (0x4A <= scheme <= 0xEF):
        raise MqttSnError("MALFORMED_PACKET", "Reserved Protection Scheme")
    if not provider.supports(scheme):
        raise MqttSnError("MALFORMED_PACKET", "Protection provider does not support scheme")


def _validate_tag_rules(
    scheme: int,
    tag_code: int,
    tag_length: int,
    provider: ProtectionProvider,
) -> None:
    if tag_length <= 0 or tag_code in (0x02, 0x03):
        raise MqttSnError("MALFORMED_PACKET", "Invalid authentication tag length")
    auth_only = provider.authentication_only(scheme)
    if not auth_only and tag_code != 0x01:
        raise MqttSnError(
            "MALFORMED_PACKET",
            "AEAD Protection Schemes require tag length code 1",
        )
    if auth_only and tag_code >= 0x04 and tag_length != tag_code * 2:
        raise MqttSnError(
            "MALFORMED_PACKET",
            "Truncated authentication tag length does not match flags",
        )


def _validate_inner_packet(packet_bytes: bytes) -> None:
    if not packet_bytes:
        raise MqttSnError("MALFORMED_PACKET", "Protected MQTT-SN Packet is missing")
    packet = decode_packet(packet_bytes)
    if packet.packet_length != len(packet_bytes):
        raise MqttSnError(
            "MALFORMED_PACKET",
            "Protection Encapsulation must contain exactly one MQTT-SN packet",
        )
    if packet.type is PacketType.FORWARDER_ENCAPSULATION:
        raise MqttSnError(
            "MALFORMED_PACKET",
            "Forwarder Encapsulation MUST NOT be protected",
        )


def _counter_code(length: int) -> int:
    values = {0: 0, 2: 1, 4: 2}
    if length not in values:
        raise ValueError("monotonic_counter must contain 0, 2, or 4 bytes")
    return values[length]


def _counter_length(code: int) -> int:
    values = {0: 0, 1: 2, 2: 4}
    if code not in values:
        raise MqttSnError("MALFORMED_PACKET", "Reserved counter length code")
    return values[code]


def _crypto_code(length: int) -> int:
    values = {0: 0, 2: 1, 4: 2, 12: 3}
    if length not in values:
        raise ValueError("cryptographic_material must contain 0, 2, 4, or 12 bytes")
    return values[length]


def _crypto_length(code: int) -> int:
    return {0: 0, 1: 2, 2: 4, 3: 12}[code]
