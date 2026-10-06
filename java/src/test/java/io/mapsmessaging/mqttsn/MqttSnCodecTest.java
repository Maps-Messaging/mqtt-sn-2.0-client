package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class MqttSnCodecTest {

  @Test
  void encodesAndDecodesShortPingReq() {
    byte[] encoded = MqttSnCodec.encode(PacketType.PINGREQ, null);

    assertArrayEquals(new byte[] {0x02, 0x0C}, encoded);

    DecodedPacket decoded = MqttSnCodec.decode(ByteBuffer.wrap(encoded));
    assertEquals(PacketType.PINGREQ, decoded.type());
    assertEquals(0, decoded.body().remaining());
    assertEquals(2, decoded.headerLength());
  }

  @Test
  void supportsThreeByteLengthFormat() {
    byte[] body = new byte[254];
    byte[] encoded = MqttSnCodec.encode(PacketType.PUBLISH, body);

    assertEquals(258, encoded.length);
    assertEquals(0x01, Byte.toUnsignedInt(encoded[0]));
    assertEquals(0x01, Byte.toUnsignedInt(encoded[1]));
    assertEquals(0x02, Byte.toUnsignedInt(encoded[2]));
    assertEquals(0x03, Byte.toUnsignedInt(encoded[3]));

    DecodedPacket decoded = MqttSnCodec.decode(ByteBuffer.wrap(encoded));
    assertEquals(4, decoded.headerLength());
    assertEquals(254, decoded.body().remaining());
  }

  @Test
  void rejectsReservedPacketType() {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decode(ByteBuffer.wrap(new byte[] {0x02, (byte) 0xFD})));
    assertEquals(MqttSnError.RESERVED_TYPE, error.error());
  }

  @Test
  void returnsConsumedPrefixForPartialTrailingPacket() {
    ByteBuffer input = ByteBuffer.wrap(new byte[] {
        0x02, 0x0C,
        0x01, 0x01
    });
    List<PacketType> types = new ArrayList<>();

    int consumed = new MqttSnClient().accept(input, packet -> types.add(packet.type()));

    assertEquals(2, consumed);
    assertEquals(List.of(PacketType.PINGREQ), types);
  }
}
