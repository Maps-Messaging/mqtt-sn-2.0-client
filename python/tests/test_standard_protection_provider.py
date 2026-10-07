"""Cross-backend vectors for all CSD01 standard protection schemes."""

import pytest

from mqttsn2.protection import ProtectionContext
from mqttsn2.providers import CryptographyProtectionProvider

PREFIX = bytes.fromhex("1200a1b2c3d4e5f60102030405060708")
PLAINTEXT = bytes.fromhex("040c1234")

VECTORS = [
    (0x00, "0b" * 20, "040c1234", "a3ae047cd0fb77256f6cbf12252733dd73075a9622780fc95be7ee03490dc8db"),
    (0x01, "0b" * 20, "040c1234", "130a16c674d3af9ee2d24dda7ec65c8e3c89806cea699ef621150b493e57861e"),
    (0x02, "2b7e151628aed2a6abf7158809cf4f3c", "040c1234", "a3e0372ca6e9ca552f310f01d9f00ba5"),
    (0x03, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "040c1234", "94d95a579745229a5a2d0f54dda3f6d1"),
    (0x04, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "040c1234", "791d72eaec7fd5ce0ecd112749a05673"),
    (0x40, "404142434445464748494a4b4c4d4e4f", "04dfc15b", "0e3b59a345150593"),
    (0x41, "404142434445464748494a4b4c4d4e4f5051525354555657", "2bdf29ea", "14ea27013b24bb50"),
    (0x42, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "358b3d1b", "387c8791681e3ed9"),
    (0x43, "404142434445464748494a4b4c4d4e4f", "04dfc15b", "577798b5f0e31ea24da56dd805a68cc5"),
    (0x44, "404142434445464748494a4b4c4d4e4f5051525354555657", "2bdf29ea", "600a13e6d7df0147d80564432d4ccaaa"),
    (0x45, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "358b3d1b", "9b002a22ba6e2f6f7e6748b88d42bf5c"),
    (0x46, "00" * 16, "2743129d", "dffa819c4fe6d41c4912a891e4c82786"),
    (0x47, "00" * 24, "631721b8", "e9a8babec89fb68f883d19425498d4cc"),
    (0x48, "00" * 32, "a9fa1bbd", "79f9e5b15a075aa22bece93beb9722cf"),
    (0x49, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "c1816b5e", "4979d51cd6ebd3132aecb6c366360ada"),
]


def context(scheme: int, tag_code: int = 0x01) -> ProtectionContext:
    return ProtectionContext(
        scheme,
        tag_code,
        bytes(8),
        bytes(4),
        b"",
        b"",
        PREFIX,
    )


@pytest.mark.parametrize(("scheme", "key_hex", "protected_hex", "tag_hex"), VECTORS)
def test_matches_cross_backend_vectors(
    scheme: int,
    key_hex: str,
    protected_hex: str,
    tag_hex: str,
) -> None:
    key = bytes.fromhex(key_hex)
    provider = CryptographyProtectionProvider(lambda _: key)
    ctx = context(scheme)

    protected = provider.protect(ctx, PLAINTEXT)

    assert protected.protected_packet == bytes.fromhex(protected_hex)
    assert protected.authentication_tag == bytes.fromhex(tag_hex)
    assert (
        provider.unprotect(
            ctx,
            protected.protected_packet,
            protected.authentication_tag,
        )
        == PLAINTEXT
    )


def test_truncates_authentication_only_tag_from_left() -> None:
    key = bytes.fromhex("0b" * 20)
    provider = CryptographyProtectionProvider(lambda _: key)

    full = provider.protect(context(0x00, 0x01), PLAINTEXT).authentication_tag
    truncated = provider.protect(context(0x00, 0x04), PLAINTEXT).authentication_tag

    assert len(truncated) == 8
    assert truncated == full[:8]


def test_rejects_tampered_aead_tag() -> None:
    key = bytes(16)
    provider = CryptographyProtectionProvider(lambda _: key)
    ctx = context(0x46)
    protected = provider.protect(ctx, PLAINTEXT)
    tag = bytearray(protected.authentication_tag)
    tag[0] ^= 1

    assert provider.unprotect(ctx, protected.protected_packet, bytes(tag)) is None
