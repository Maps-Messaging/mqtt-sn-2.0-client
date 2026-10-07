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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

/**
 * MQTT-SN 2.0 CSD01: §3.6.1 PUBWOS and §3.20 Gateway Discovery Packets.
 * Relevant requirements include MQTT-SN-3.6.1.2-1/-2,
 * MQTT-SN-3.6.1.2.1-1, MQTT-SN-3.6.1.4-1/-2 and MQTT-SN-3.6.1.6-1.
 */
class OptionalPacketCodecTest {

  @Test
  void pubWosTopicNameMatchesCsd01WireShape() {
    byte[] encoded = MqttSnCodec.encodePubWos(
        new PubWosPacket(false, TopicRef.name("a/b"), new byte[] {'x'}));

    assertArrayEquals(
        new byte[] {0x09, 0x12, 0x03, 0x00, 0x03, 'a', '/', 'b', 'x'},
        encoded);

    PubWosPacket decoded = MqttSnCodec.decodePubWos(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));
    assertEquals("a/b", decoded.topic().name());
    assertArrayEquals(new byte[] {'x'}, decoded.payload());
  }

  @Test
  void pubWosPredefinedAliasAndRetainRoundTrip() {
    byte[] encoded = MqttSnCodec.encodePubWos(
        new PubWosPacket(true, TopicRef.predefinedAlias(42), new byte[0]));
    PubWosPacket decoded = MqttSnCodec.decodePubWos(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));

    assertEquals(42, decoded.topic().alias());
    assertEquals(true, decoded.retain());
  }

  @Test
  void pubWosRejectsSessionAliasAndReservedFlags() {
    TopicRef sessionAlias = TopicRef.sessionAlias(1);
    assertThrows(
        IllegalArgumentException.class,
        () -> new PubWosPacket(false, sessionAlias, new byte[0]));

    DecodedPacket encoded = MqttSnCodec.decode(ByteBuffer.wrap(
        new byte[] {0x05, 0x12, 0x20, 0x00, 0x01}));
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodePubWos(encoded));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void advertiseRoundTrip() {
    byte[] encoded = MqttSnCodec.encodeAdvertise(new AdvertisePacket(7, 60));
    assertArrayEquals(new byte[] {0x05, 0x16, 0x07, 0x00, 0x3C}, encoded);

    AdvertisePacket decoded = MqttSnCodec.decodeAdvertise(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));
    assertEquals(7, decoded.gatewayIdentifier());
    assertEquals(60, decoded.durationSeconds());
  }

  @Test
  void searchGwCarriesOpaqueNetworkInformation() {
    byte[] encoded = MqttSnCodec.encodeSearchGw(
        new SearchGwPacket(new byte[] {0x01, 0x02}));
    assertArrayEquals(new byte[] {0x04, 0x17, 0x01, 0x02}, encoded);

    SearchGwPacket decoded = MqttSnCodec.decodeSearchGw(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));
    assertArrayEquals(new byte[] {0x01, 0x02}, decoded.additionalNetworkInformation());
  }

  @Test
  void gwInfoCarriesOptionalGatewayAddress() {
    byte[] encoded = MqttSnCodec.encodeGwInfo(
        new GwInfoPacket(7, new byte[] {(byte) 192, (byte) 168, 1, 1}));
    assertArrayEquals(
        new byte[] {0x07, 0x18, 0x07, (byte) 192, (byte) 168, 1, 1},
        encoded);

    GwInfoPacket decoded = MqttSnCodec.decodeGwInfo(
        MqttSnCodec.decode(ByteBuffer.wrap(encoded)));
    assertEquals(7, decoded.gatewayIdentifier());
    assertArrayEquals(
        new byte[] {(byte) 192, (byte) 168, 1, 1},
        decoded.gatewayAddress());
  }
}
