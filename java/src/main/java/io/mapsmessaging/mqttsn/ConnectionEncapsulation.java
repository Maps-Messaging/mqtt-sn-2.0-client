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

public record ConnectionEncapsulation(String clientIdentifier, byte[] mqttSnPacket) {
  public ConnectionEncapsulation {
    clientIdentifier = clientIdentifier == null ? "" : clientIdentifier;
    MqttSnUtf8.validate(clientIdentifier);
    byte[] clientId = clientIdentifier.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    if (clientId.length > 0xFFFF) {
      throw new IllegalArgumentException("clientIdentifier exceeds 65535 UTF-8 bytes");
    }
    mqttSnPacket = mqttSnPacket == null ? new byte[0] : mqttSnPacket.clone();
  }

  @Override
  public byte[] mqttSnPacket() {
    return mqttSnPacket.clone();
  }
}
