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

import hashlib
import hmac as stdlib_hmac
from collections.abc import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305

from ..protection import ProtectedContent, ProtectionContext


KeyResolver = Callable[[ProtectionContext], bytes]


class CryptographyProtectionProvider:
    """CSD01 standard protection schemes using pyca/cryptography."""

    def __init__(self, key_resolver: KeyResolver) -> None:
        self._key_resolver = key_resolver

    def supports(self, scheme: int) -> bool:
        return 0x00 <= scheme <= 0x04 or 0x40 <= scheme <= 0x49

    def authentication_only(self, scheme: int) -> bool:
        return 0x00 <= scheme <= 0x04

    def authentication_tag_length(self, scheme: int, tag_length_code: int) -> int:
        if not self.supports(scheme) or tag_length_code in (0x02, 0x03):
            return 0

        nominal = {
            0x00: 32,
            0x01: 32,
            0x02: 16,
            0x03: 16,
            0x04: 16,
            0x40: 8,
            0x41: 8,
            0x42: 8,
            0x43: 16,
            0x44: 16,
            0x45: 16,
            0x46: 16,
            0x47: 16,
            0x48: 16,
            0x49: 16,
        }[scheme]

        if not self.authentication_only(scheme):
            return nominal if tag_length_code == 0x01 else 0

        if tag_length_code in (0x00, 0x01):
            return nominal
        if tag_length_code >= 0x04:
            truncated = tag_length_code * 2
            return truncated if truncated <= nominal else 0
        return 0

    def protected_packet_length(self, scheme: int, mqttsn_packet_length: int) -> int:
        return mqttsn_packet_length if self.supports(scheme) else 0

    def protect(
        self,
        context: ProtectionContext,
        mqttsn_packet: bytes,
    ) -> ProtectedContent:
        key = self._resolve_key(context)
        self._validate_key_length(context.scheme, len(key))

        if self.authentication_only(context.scheme):
            full_tag = self._mac(context, key, mqttsn_packet)
            tag_length = self.authentication_tag_length(
                context.scheme, context.tag_length_code
            )
            return ProtectedContent(mqttsn_packet, full_tag[:tag_length])

        combined = self._aead_encrypt(context, key, mqttsn_packet)
        tag_length = self.authentication_tag_length(
            context.scheme, context.tag_length_code
        )
        return ProtectedContent(combined[:-tag_length], combined[-tag_length:])

    def unprotect(
        self,
        context: ProtectionContext,
        protected_packet: bytes,
        authentication_tag: bytes,
    ) -> bytes | None:
        key = self._resolve_key(context)
        self._validate_key_length(context.scheme, len(key))

        if self.authentication_only(context.scheme):
            full_tag = self._mac(context, key, protected_packet)
            expected = full_tag[: len(authentication_tag)]
            return (
                bytes(protected_packet)
                if stdlib_hmac.compare_digest(expected, authentication_tag)
                else None
            )

        try:
            return self._aead_decrypt(
                context,
                key,
                protected_packet + authentication_tag,
            )
        except InvalidTag:
            return None

    def _mac(
        self,
        context: ProtectionContext,
        key: bytes,
        packet: bytes,
    ) -> bytes:
        data = context.authenticated_prefix + packet
        if context.scheme == 0x00:
            algorithm = hashes.SHA256()
            mac = hmac.HMAC(key, algorithm)
        elif context.scheme == 0x01:
            algorithm = hashes.SHA3_256()
            mac = hmac.HMAC(key, algorithm)
        elif context.scheme in (0x02, 0x03, 0x04):
            mac = CMAC(algorithms.AES(key))
        else:
            raise ValueError("not an authentication-only scheme")

        mac.update(data)
        return mac.finalize()

    def _aead_encrypt(
        self,
        context: ProtectionContext,
        key: bytes,
        plaintext: bytes,
    ) -> bytes:
        nonce = self._derive_nonce(context)
        aad = context.authenticated_prefix

        if context.scheme in range(0x40, 0x46):
            tag_length = self.authentication_tag_length(
                context.scheme, context.tag_length_code
            )
            return AESCCM(key, tag_length=tag_length).encrypt(nonce, plaintext, aad)
        if context.scheme in range(0x46, 0x49):
            return AESGCM(key).encrypt(nonce, plaintext, aad)
        if context.scheme == 0x49:
            return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        raise ValueError("not an AEAD scheme")

    def _aead_decrypt(
        self,
        context: ProtectionContext,
        key: bytes,
        combined: bytes,
    ) -> bytes:
        nonce = self._derive_nonce(context)
        aad = context.authenticated_prefix

        if context.scheme in range(0x40, 0x46):
            tag_length = self.authentication_tag_length(
                context.scheme, context.tag_length_code
            )
            return AESCCM(key, tag_length=tag_length).decrypt(nonce, combined, aad)
        if context.scheme in range(0x46, 0x49):
            return AESGCM(key).decrypt(nonce, combined, aad)
        if context.scheme == 0x49:
            return ChaCha20Poly1305(key).decrypt(nonce, combined, aad)
        raise ValueError("not an AEAD scheme")

    @staticmethod
    def _derive_nonce(context: ProtectionContext) -> bytes:
        digest = hashlib.sha256(context.authenticated_prefix).digest()
        if 0x40 <= context.scheme <= 0x45:
            return digest[:13]
        if 0x46 <= context.scheme <= 0x49:
            return digest[:12]
        raise ValueError("scheme has no AEAD nonce")

    def _resolve_key(self, context: ProtectionContext) -> bytes:
        key = self._key_resolver(context)
        if not key:
            raise ValueError("no key available for protection context")
        return bytes(key)

    @staticmethod
    def _validate_key_length(scheme: int, length: int) -> None:
        expected = {
            0x00: None,
            0x01: None,
            0x02: 16,
            0x03: 24,
            0x04: 32,
            0x40: 16,
            0x41: 24,
            0x42: 32,
            0x43: 16,
            0x44: 24,
            0x45: 32,
            0x46: 16,
            0x47: 24,
            0x48: 32,
            0x49: 32,
        }.get(scheme, 0)

        if expected is None:
            if length == 0:
                raise ValueError("HMAC key must not be empty")
        elif length != expected:
            raise ValueError(
                f"invalid key length {length} for protection scheme 0x{scheme:02X}"
            )
