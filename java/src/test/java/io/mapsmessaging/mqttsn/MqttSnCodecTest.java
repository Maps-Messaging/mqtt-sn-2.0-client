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

  @Test
  void encodesStrictBaseConnect() {
    ConnectOptions options = new ConnectOptions(
        true, false, false, 0x1234, 60, 0, "client1");

    byte[] encoded = MqttSnCodec.encodeConnect(options);

    assertArrayEquals(
        new byte[] {
            0x11, 0x01, 0x01, 0x12, 0x34, 0x02, 0x00, 0x3C,
            0x00, 0x00, 'c', 'l', 'i', 'e', 'n', 't', '1'
        },
        encoded);
  }

  @Test
  void decodesConnAckWithSuggestedValues() {
    byte[] encoded = new byte[] {
        0x0C, 0x02,
        0x06,
        0x12, 0x34,
        0x00,
        0x00, 0x00, 0x00, 0x78,
        0x00, 0x3C
    };

    ConnAck connAck = MqttSnCodec.decodeConnAck(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));

    assertEquals(0x1234, connAck.packetIdentifier());
    assertEquals(0, connAck.reasonCode());
    assertEquals(120L, connAck.sessionExpiryInterval());
    assertEquals(60, connAck.serverKeepAlive());
  }

  @Test
  void rejectsConnAckReservedFlags() {
    DecodedPacket packet = MqttSnCodec.decode(
        ByteBuffer.wrap(new byte[] {0x06, 0x02, (byte) 0x80, 0x00, 0x01, 0x00}));

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeConnAck(packet));

    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void rejectsNullInMqttSnUtf8() {
    assertThrows(
        MqttSnException.class,
        () -> new ConnectOptions(true, false, false, 1, 60, 0, "a\0b"));
  }

}
