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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * MQTT-SN 2.0 CSD01 MQTT-SN-3.1.2.3-1/-2 and section 4.11.1.
 */
class ConnectAuthenticationTest {

  @Test
  void authenticatedConnectCarriesMethodAndInitialData() {
    ConnectOptions options =
        new ConnectOptions(true, false, false, 0x1234, 60, 0, "client1");

    byte[] encoded = MqttSnCodec.encodeConnect(
        options,
        "PLAIN",
        new byte[] {0x01, 0x02, 0x03});

    assertArrayEquals(
        new byte[] {
            0x1C, 0x01,
            0x05,
            0x12, 0x34,
            0x02,
            0x00, 0x3C,
            0x00, 0x00,
            0x05, 'P', 'L', 'A', 'I', 'N',
            0x00, 0x03, 0x01, 0x02, 0x03,
            'c', 'l', 'i', 'e', 'n', 't', '1'
        },
        encoded);
  }

  @Test
  void unauthenticatedConnectRemainsBackwardCompatible() {
    ConnectOptions options =
        new ConnectOptions(true, false, false, 0x1234, 60, 0, "client1");

    assertArrayEquals(
        MqttSnCodec.encodeConnect(options),
        MqttSnCodec.encodeConnect(options, null, null));
  }

  @Test
  void authenticationDataRequiresMethod() {
    ConnectOptions options =
        new ConnectOptions(true, false, false, 0x1234, 60, 0, "client1");

    assertThrows(
        IllegalArgumentException.class,
        () -> MqttSnCodec.encodeConnect(options, null, new byte[] {1}));
  }
}
