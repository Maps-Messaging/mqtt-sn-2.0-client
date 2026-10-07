package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class AuthCodecTest {

  @Test
  void roundTripsAuthenticationMethodAndData() {
    AuthPacket auth = new AuthPacket(
        0x1234, 0x18, "psk", new byte[] {0x01, 0x02, 0x03});

    byte[] encoded = MqttSnCodec.encodeAuth(auth);
    AuthPacket decoded = MqttSnCodec.decodeAuth(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));

    assertEquals(0x1234, decoded.packetIdentifier());
    assertEquals(0x18, decoded.reasonCode());
    assertEquals("psk", decoded.authenticationMethod());
    assertArrayEquals(new byte[] {0x01, 0x02, 0x03}, decoded.authenticationData());
  }

  @Test
  void rejectsZeroIdentifierAndTruncatedMethod() {
    assertMalformed(new byte[] {0x06, 0x0F, 0x00, 0x00, 0x18, 0x00});
    assertMalformed(new byte[] {0x07, 0x0F, 0x12, 0x34, 0x18, 0x03, 'p'});
  }

  private static void assertMalformed(byte[] bytes) {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeAuth(MqttSnCodec.decode(ByteBuffer.wrap(bytes))));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }
}
