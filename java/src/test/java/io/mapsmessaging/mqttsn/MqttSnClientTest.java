package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class MqttSnClientTest {

  @Test
  void acceptsMultipleCompletePacketsWithoutChangingInputPosition() {
    ByteBuffer input = ByteBuffer.wrap(new byte[] {
        0x02, 0x0C,
        0x02, 0x0D
    });
    input.position(0);
    List<PacketType> packets = new ArrayList<>();

    int consumed = new MqttSnClient().accept(input, packet -> packets.add(packet.type()));

    assertEquals(4, consumed);
    assertEquals(List.of(PacketType.PINGREQ, PacketType.PINGRESP), packets);
    assertEquals(0, input.position());
  }

  @Test
  void leavesIncompleteTrailingPacketUnconsumed() {
    ByteBuffer input = ByteBuffer.wrap(new byte[] {
        0x02, 0x0C,
        0x01, 0x00
    });
    List<PacketType> packets = new ArrayList<>();

    int consumed = new MqttSnClient().accept(input, packet -> packets.add(packet.type()));

    assertEquals(2, consumed);
    assertEquals(List.of(PacketType.PINGREQ), packets);
  }

  @Test
  void propagatesProtocolErrorsRatherThanTreatingThemAsPartialData() {
    ByteBuffer input = ByteBuffer.wrap(new byte[] {0x02, (byte) 0xFD});

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> new MqttSnClient().accept(input, packet -> { }));

    assertEquals(MqttSnError.RESERVED_TYPE, error.error());
  }

  @Test
  void honoursNonZeroInputPosition() {
    ByteBuffer input = ByteBuffer.wrap(new byte[] {
        0x55, 0x55,
        0x02, 0x0C,
        0x02, 0x0D
    });
    input.position(2);
    List<PacketType> packets = new ArrayList<>();

    int consumed = new MqttSnClient().accept(input, packet -> packets.add(packet.type()));

    assertEquals(4, consumed);
    assertEquals(List.of(PacketType.PINGREQ, PacketType.PINGRESP), packets);
    assertEquals(2, input.position());
  }

  @Test
  void genericEncodeDelegatesToCodec() {
    assertEquals(
        List.of((byte) 0x02, (byte) 0x15),
        bytes(new MqttSnClient().encode(PacketType.WAKEUP, null)));
  }

  private static List<Byte> bytes(byte[] data) {
    List<Byte> result = new ArrayList<>(data.length);
    for (byte value : data) {
      result.add(value);
    }
    return result;
  }
}
