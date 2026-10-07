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

public record AuthPacket(
    int packetIdentifier,
    int reasonCode,
    String authenticationMethod,
    byte[] authenticationData) {

  public AuthPacket {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    if (reasonCode < 0 || reasonCode > 0xFF) {
      throw new IllegalArgumentException("reasonCode must be 0..255");
    }
    authenticationMethod = authenticationMethod == null ? "" : authenticationMethod;
    MqttSnUtf8.validate(authenticationMethod);
    byte[] method = authenticationMethod.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    if (method.length > 0xFF) {
      throw new IllegalArgumentException("authenticationMethod must be at most 255 UTF-8 bytes");
    }
    authenticationData = authenticationData == null ? new byte[0] : authenticationData.clone();
  }

  @Override
  public byte[] authenticationData() {
    return authenticationData.clone();
  }
}
