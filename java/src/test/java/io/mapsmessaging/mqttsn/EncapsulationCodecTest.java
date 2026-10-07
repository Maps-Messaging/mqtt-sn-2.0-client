package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

/**
 * MQTT-SN 2.0 CSD01 §3.18 Connection Encapsulation and
 * §3.19 Forwarder Encapsulation.
 * Covers MQTT-SN-3.18-3/-4 and exact embedded-packet framing.
 */
class EncapsulationCodecTest {

  @Test
  void connectionEncapsulationRoundTripsAllowedClientPacket() {
    byte[] inner = MqttSnCodec.encodePingReq(0x1234);
    byte[] encoded = MqttSnCodec.encodeConnectionEncapsulation(
        new ConnectionEncapsulation("client1", inner));

    assertArrayEquals(
        new byte[] {
            0x0F, (byte) 0xFE,
            0x00, 0x07,
            'c', 'l', 'i', 'e', 'n', 't', '1',
            0x04, 0x0C, 0x12, 0x34
        },
        encoded);

    ConnectionEncapsulation decoded = MqttSnCodec.decodeConnectionEncapsulation(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));
    assertEquals("client1", decoded.clientIdentifier());
    assertArrayEquals(inner, decoded.mqttSnPacket());
  }

  @Test
  void connectionEncapsulationRejectsDisallowedInnerPacket() {
    byte[] connAck = new byte[] {0x06, 0x02, 0x00, 0x12, 0x34, 0x00};

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.encodeConnectionEncapsulation(
            new ConnectionEncapsulation("client1", connAck)));

    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void connectionEncapsulationRejectsMultipleInnerPackets() {
    byte[] twoPackets = new byte[] {
        0x04, 0x0C, 0x12, 0x34,
        0x04, 0x0C, 0x56, 0x78
    };

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.encodeConnectionEncapsulation(
            new ConnectionEncapsulation("client1", twoPackets)));

    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void forwarderEncapsulationRoundTripsOpaqueAddressing() {
    byte[] inner = MqttSnCodec.encodePingReq(0x1234);
    byte[] encoded = MqttSnCodec.encodeForwarderEncapsulation(
        new ForwarderEncapsulation(new byte[] {0x01, 0x02}, inner));

    assertArrayEquals(
        new byte[] {
            0x09, (byte) 0xFC,
            0x02, 0x01, 0x02,
            0x04, 0x0C, 0x12, 0x34
        },
        encoded);

    ForwarderEncapsulation decoded = MqttSnCodec.decodeForwarderEncapsulation(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));
    assertArrayEquals(new byte[] {0x01, 0x02}, decoded.clientAddressingInformation());
    assertArrayEquals(inner, decoded.mqttSnPacket());
  }

  @Test
  void forwarderEncapsulationRejectsMissingInnerPacket() {
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeForwarderEncapsulation(
            MqttSnCodec.decode(ByteBuffer.wrap(
                new byte[] {0x04, (byte) 0xFC, 0x01, 0x55}))));

    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }
}
