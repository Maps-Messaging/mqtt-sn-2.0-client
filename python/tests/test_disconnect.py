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
