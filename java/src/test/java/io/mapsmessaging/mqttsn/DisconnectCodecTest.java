package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class DisconnectCodecTest {

  @Test
  void roundTripsAllOptionalDisconnectFields() {
    DisconnectOptions options = new DisconnectOptions(
        0x1234, 0x82, 3600L, "protocol error");

    byte[] encoded = MqttSnCodec.encodeDisconnect(options);
    DisconnectPacket decoded = MqttSnCodec.decodeDisconnect(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));

    assertEquals(0x1234, decoded.packetIdentifier());
    assertEquals(0x82, decoded.reasonCode());
    assertEquals(3600L, decoded.sessionExpiryInterval());
    assertEquals("protocol error", decoded.reasonString());
  }

  @Test
  void supportsMinimalDisconnect() {
    byte[] encoded = MqttSnCodec.encodeDisconnect(
        new DisconnectOptions(null, null, null, ""));

    assertEquals(0x03, Byte.toUnsignedInt(encoded[0]));
    assertEquals(PacketType.DISCONNECT.value(), Byte.toUnsignedInt(encoded[1]));
    assertEquals(0, Byte.toUnsignedInt(encoded[2]));
  }

  @Test
  void rejectsReservedFlagsAndZeroPacketIdentifier() {
    assertMalformed(new byte[] {0x03, 0x0E, (byte) 0x80});
    assertMalformed(new byte[] {0x05, 0x0E, 0x01, 0x00, 0x00});
  }

  private static void assertMalformed(byte[] bytes) {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeDisconnect(MqttSnCodec.decode(ByteBuffer.wrap(bytes))));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }
}
