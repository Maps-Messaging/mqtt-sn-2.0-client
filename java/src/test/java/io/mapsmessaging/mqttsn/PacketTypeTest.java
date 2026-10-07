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

import org.junit.jupiter.api.Test;

class PacketTypeTest {

  @Test
  void allCsd01PacketValuesRoundTrip() {
    for (PacketType type : PacketType.values()) {
      assertEquals(type, PacketType.fromValue(type.value()));
    }
  }

  @Test
  void reservedPacketTypesAreRejected() {
    for (int value : new int[] {0x00, 0x19, 0x7F, 0xFB, 0xFD}) {
      MqttSnException error = assertThrows(
          MqttSnException.class, () -> PacketType.fromValue(value));
      assertEquals(MqttSnError.RESERVED_TYPE, error.error());
    }
  }

  @Test
  void inputIsTreatedAsUnsignedByte() {
    assertEquals(PacketType.PROTECTION_ENCAPSULATION, PacketType.fromValue(-1));
  }
}
