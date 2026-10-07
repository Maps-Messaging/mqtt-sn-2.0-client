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
