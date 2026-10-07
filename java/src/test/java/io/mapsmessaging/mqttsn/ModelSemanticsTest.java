package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import org.junit.jupiter.api.Test;

class ModelSemanticsTest {

  @Test
  void decodedPacketBodyIsReadOnlyAndRetainsIndependentViewState() {
    ByteBuffer source = ByteBuffer.wrap(new byte[] {1, 2, 3});
    DecodedPacket packet = new DecodedPacket(PacketType.PUBLISH, source, 5, 2);

    assertTrue(packet.body().isReadOnly());
    assertThrows(ReadOnlyBufferException.class, () -> packet.body().put((byte) 9));

    ByteBuffer first = packet.body();
    first.get();
    assertEquals(0, packet.body().position());
  }

  @Test
  void connAckAuthenticationDataIsDefensivelyCopied() {
    byte[] data = {1, 2, 3};
    ConnAck connAck = new ConnAck(
        false, 1, 0, null, null, "psk", data, "");

    data[0] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, connAck.authenticationData());

    byte[] returned = connAck.authenticationData();
    returned[1] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, connAck.authenticationData());
  }

  @Test
  void publishPacketPayloadIsDefensivelyCopied() {
    byte[] data = {4, 5, 6};
    PublishPacket packet = new PublishPacket(
        QoS.AT_MOST_ONCE, false, false, 0, TopicRef.name("a/b"), data);

    data[0] = 9;
    assertArrayEquals(new byte[] {4, 5, 6}, packet.payload());

    byte[] returned = packet.payload();
    returned[1] = 9;
    assertArrayEquals(new byte[] {4, 5, 6}, packet.payload());
  }

  @Test
  void exceptionPreservesErrorCategory() {
    MqttSnException exception = new MqttSnException(
        MqttSnError.NEED_MORE, "partial");

    assertEquals(MqttSnError.NEED_MORE, exception.error());
    assertEquals("partial", exception.getMessage());
  }

  @Test
  void qosAndTopicTypeRejectReservedWireValues() {
    MqttSnException qos = assertThrows(
        MqttSnException.class, () -> QoS.fromValue(3));
    assertEquals(MqttSnError.MALFORMED_PACKET, qos.error());

    MqttSnException topic = assertThrows(
        MqttSnException.class, () -> TopicType.fromValue(2));
    assertEquals(MqttSnError.MALFORMED_PACKET, topic.error());
  }
}
