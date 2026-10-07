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

public record DisconnectOptions(
    Integer packetIdentifier,
    Integer reasonCode,
    Long sessionExpiryInterval,
    String reasonString) {

  public DisconnectOptions {
    if (packetIdentifier != null && (packetIdentifier < 1 || packetIdentifier > 0xFFFF)) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535 when present");
    }
    if (reasonCode != null && (reasonCode < 0 || reasonCode > 0xFF)) {
      throw new IllegalArgumentException("reasonCode must be 0..255 when present");
    }
    if (sessionExpiryInterval != null
        && (sessionExpiryInterval < 0 || sessionExpiryInterval > 0xFFFF_FFFFL)) {
      throw new IllegalArgumentException("sessionExpiryInterval must be 0..4294967295 when present");
    }
    reasonString = reasonString == null ? "" : reasonString;
    MqttSnUtf8.validate(reasonString);
  }
}
