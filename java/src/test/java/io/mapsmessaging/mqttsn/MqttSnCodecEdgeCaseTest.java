/**
 *
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class MqttSnCodecEdgeCaseTest {

  @Test
  void usesShortLengthThrough255BytesAndExtendedLengthAboveIt() {
    byte[] shortBody = new byte[253];
    byte[] shortPacket = MqttSnCodec.encode(PacketType.PUBLISH, shortBody);
    assertEquals(255, shortPacket.length);
    assertEquals(255, Byte.toUnsignedInt(shortPacket[0]));
    assertEquals(2, MqttSnCodec.decode(ByteBuffer.wrap(shortPacket)).headerLength());

    byte[] extendedBody = new byte[254];
    byte[] extendedPacket = MqttSnCodec.encode(PacketType.PUBLISH, extendedBody);
    assertEquals(258, extendedPacket.length);
    assertArrayEquals(
        new byte[] {0x01, 0x01, 0x02, 0x03},
        java.util.Arrays.copyOf(extendedPacket, 4));
    assertEquals(4, MqttSnCodec.decode(ByteBuffer.wrap(extendedPacket)).headerLength());
  }

  @Test
  void supportsMaximumPacketSizeAndRejectsLargerPacket() {
    byte[] maximumBody = new byte[MqttSnCodec.MAX_PACKET_SIZE - 4];
    byte[] maximumPacket = MqttSnCodec.encode(PacketType.PUBLISH, maximumBody);

    assertEquals(MqttSnCodec.MAX_PACKET_SIZE, maximumPacket.length);
    assertEquals(MqttSnCodec.MAX_PACKET_SIZE,
        MqttSnCodec.decode(ByteBuffer.wrap(maximumPacket)).packetLength());

    byte[] tooLargeBody = new byte[MqttSnCodec.MAX_PACKET_SIZE - 3];
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.encode(PacketType.PUBLISH, tooLargeBody));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void rejectsMalformedAndTruncatedLengthHeaders() {
    assertError(MqttSnError.MALFORMED_PACKET, new byte[] {0x00});
    assertError(MqttSnError.NEED_MORE, new byte[] {0x01});
    assertError(MqttSnError.NEED_MORE, new byte[] {0x01, 0x00});
    assertError(MqttSnError.NEED_MORE, new byte[] {0x01, 0x00, 0x04});
    assertError(MqttSnError.MALFORMED_PACKET, new byte[] {0x01, 0x00, 0x03, 0x0C});
  }

  @Test
  void decodeReturnsFirstPacketWithoutConsumingTrailingBytes() {
    ByteBuffer buffer = ByteBuffer.wrap(new byte[] {
        0x02, 0x0C,
        0x02, 0x0D
    });

    DecodedPacket packet = MqttSnCodec.decode(buffer);

    assertEquals(PacketType.PINGREQ, packet.type());
    assertEquals(2, packet.packetLength());
    assertEquals(0, buffer.position());
  }

  @Test
  void connAckDecodesAuthenticationAndAssignedClientIdentifier() {
    byte[] packetBytes = new byte[] {
        0x12, 0x02,
        0x08,
        0x12, 0x34,
        0x00,
        0x03, 'p', 's', 'k',
        0x00, 0x02, 0x01, 0x02,
        'i', 'd', '4', '2'
    };

    ConnAck connAck = MqttSnCodec.decodeConnAck(
        MqttSnCodec.decode(ByteBuffer.wrap(packetBytes)));

    assertFalse(connAck.sessionPresent());
    assertEquals("psk", connAck.authenticationMethod());
    assertArrayEquals(new byte[] {0x01, 0x02}, connAck.authenticationData());
    assertEquals("id42", connAck.assignedClientIdentifier());
  }

  @Test
  void connAckRejectsZeroPacketIdentifierAndMalformedOptionalFields() {
    assertConnAckMalformed(new byte[] {0x06, 0x02, 0x00, 0x00, 0x00, 0x00});
    assertConnAckMalformed(new byte[] {0x08, 0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00});
    assertConnAckMalformed(new byte[] {0x08, 0x02, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00});
    assertConnAckMalformed(new byte[] {0x08, 0x02, 0x08, 0x00, 0x01, 0x00, 0x03, 'p'});
  }

  @Test
  void publishCoversQosOneQosTwoAndAliases() {
    PublishOptions qos1 = new PublishOptions(
        QoS.AT_LEAST_ONCE,
        false,
        true,
        0x1234,
        TopicRef.sessionAlias(42),
        new byte[] {1, 2});
    byte[] qos1Bytes = MqttSnCodec.encodePublish(qos1);
    PublishPacket qos1Decoded = MqttSnCodec.decodePublish(
        MqttSnCodec.decode(ByteBuffer.wrap(qos1Bytes)));

    assertEquals(QoS.AT_LEAST_ONCE, qos1Decoded.qos());
    assertEquals(0x1234, qos1Decoded.packetIdentifier());
    assertEquals(TopicType.SESSION_ALIAS, qos1Decoded.topic().type());
    assertEquals(42, qos1Decoded.topic().alias());
    assertTrue(qos1Decoded.retain());

    PublishOptions qos2 = new PublishOptions(
        QoS.EXACTLY_ONCE,
        true,
        false,
        0xFFFF,
        TopicRef.predefinedAlias(7),
        new byte[0]);
    PublishPacket qos2Decoded = MqttSnCodec.decodePublish(
        MqttSnCodec.decode(ByteBuffer.wrap(MqttSnCodec.encodePublish(qos2))));
    assertEquals(QoS.EXACTLY_ONCE, qos2Decoded.qos());
    assertTrue(qos2Decoded.duplicate());
    assertEquals(7, qos2Decoded.topic().alias());
  }

  @Test
  void publishRejectsReservedFlagsZeroAliasAndTruncation() {
    assertPublishMalformed(new byte[] {0x06, 0x03, 0x04, 0x00, 0x01, 0x00});
    assertPublishMalformed(new byte[] {0x05, 0x03, 0x00, 0x00, 0x00});
    assertPublishMalformed(new byte[] {0x07, 0x03, 0x20, 0x00, 0x00, 0x00, 0x01});
    assertPublishMalformed(new byte[] {0x06, 0x03, 0x03, 0x00, 0x03, 'a'});
  }

  @Test
  void subscribeEncodesAliasesAndAllOptionBits() {
    SubscribeOptions options = new SubscribeOptions(
        0x1234,
        TopicRef.predefinedAlias(9),
        2,
        true,
        QoS.EXACTLY_ONCE,
        true);

    byte[] packet = MqttSnCodec.encodeSubscribe(options);

    assertArrayEquals(
        new byte[] {0x07, 0x08, (byte) 0xD9, 0x12, 0x34, 0x00, 0x09},
        packet);
  }

  @Test
  void subAckRejectsZeroPacketIdentifierReservedFlagsAndInvalidAlias() {
    assertSubAckMalformed(new byte[] {0x05, 0x09, 0x00, 0x00, 0x00});
    assertSubAckMalformed(new byte[] {0x05, 0x09, (byte) 0x80, 0x00, 0x01});
    assertSubAckMalformed(new byte[] {0x07, 0x09, 0x04, 0x00, 0x01, 0x00, 0x00});
  }

  @Test
  void acknowledgementsSupportAllApplicablePacketTypes() {
    for (PacketType type : new PacketType[] {
        PacketType.PUBACK,
        PacketType.PUBREC,
        PacketType.PUBREL,
        PacketType.PUBCOMP,
        PacketType.UNSUBACK}) {
      byte[] encoded = MqttSnCodec.encodeAck(type, 0x1234, 0x80);
      Ack decoded = MqttSnCodec.decodeAck(
          MqttSnCodec.decode(ByteBuffer.wrap(encoded)));
      assertEquals(0x1234, decoded.packetIdentifier());
      assertEquals(0x80, decoded.reasonCode());
    }

    assertThrows(IllegalArgumentException.class,
        () -> MqttSnCodec.encodeAck(PacketType.PINGRESP, 1, null));
  }

  @Test
  void pingResponseSupportsOptionalRemainingCount() {
    PingResp withoutCount = MqttSnCodec.decodePingResp(
        MqttSnCodec.decode(ByteBuffer.wrap(new byte[] {0x04, 0x0D, 0x12, 0x34})));
    assertEquals(null, withoutCount.applicationMessagesRemaining());

    PingResp withCount = MqttSnCodec.decodePingResp(
        MqttSnCodec.decode(ByteBuffer.wrap(new byte[] {0x05, 0x0D, 0x12, 0x34, (byte) 0xFF})));
    assertEquals(255, withCount.applicationMessagesRemaining());
  }

  @Test
  void sleepResponseValidatesFlagsDurationAndTrailingData() {
    assertSleepRespMalformed(new byte[] {0x06, 0x14, 0x02, 0x12, 0x34, 0x00});
    assertSleepRespMalformed(new byte[] {
        0x09, 0x14, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00
    });
    assertSleepRespMalformed(new byte[] {
        0x0B, 0x14, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x01
    });
  }

  @Test
  void wakeupHasNoBody() {
    assertArrayEquals(new byte[] {0x02, 0x15}, MqttSnCodec.encodeWakeup());
  }

  private static void assertError(MqttSnError expected, byte[] packet) {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decode(ByteBuffer.wrap(packet)));
    assertEquals(expected, error.error());
  }

  private static void assertConnAckMalformed(byte[] bytes) {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeConnAck(MqttSnCodec.decode(ByteBuffer.wrap(bytes))));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  private static void assertPublishMalformed(byte[] bytes) {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodePublish(MqttSnCodec.decode(ByteBuffer.wrap(bytes))));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  private static void assertSubAckMalformed(byte[] bytes) {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeSubAck(MqttSnCodec.decode(ByteBuffer.wrap(bytes))));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  private static void assertSleepRespMalformed(byte[] bytes) {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeSleepResp(MqttSnCodec.decode(ByteBuffer.wrap(bytes))));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }
}
