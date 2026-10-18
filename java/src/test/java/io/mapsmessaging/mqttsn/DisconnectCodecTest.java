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
    DecodedPacket packet = MqttSnCodec.decode(ByteBuffer.wrap(bytes));
    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> MqttSnCodec.decodeDisconnect(packet));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }
}
