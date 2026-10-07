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

public enum TopicType {
  SESSION_ALIAS(0),
  PREDEFINED_ALIAS(1),
  NAME(3);

  private final int value;

  TopicType(int value) {
    this.value = value;
  }

  public int value() {
    return value;
  }

  static TopicType fromValue(int value) {
    return switch (value) {
      case 0 -> SESSION_ALIAS;
      case 1 -> PREDEFINED_ALIAS;
      case 3 -> NAME;
      default -> throw new MqttSnException(
          MqttSnError.MALFORMED_PACKET, "Reserved MQTT-SN topic type");
    };
  }
}
