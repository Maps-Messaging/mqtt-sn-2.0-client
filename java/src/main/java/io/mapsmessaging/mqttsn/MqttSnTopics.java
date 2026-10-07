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

final class MqttSnTopics {
  private MqttSnTopics() {
  }

  static void validateName(String value) {
    MqttSnUtf8.validate(value);
    if (value.isEmpty()) {
      throw malformed("Topic Name must not be empty");
    }
    if (value.indexOf('+') >= 0 || value.indexOf('#') >= 0) {
      throw malformed("Topic Name must not contain wildcards");
    }
    if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 0xFFFF) {
      throw malformed("Topic Name exceeds 65535 UTF-8 bytes");
    }
  }

  static void validateFilter(String value) {
    MqttSnUtf8.validate(value);
    if (value.isEmpty()) {
      throw malformed("Topic Filter must not be empty");
    }
    if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 0xFFFF) {
      throw malformed("Topic Filter exceeds 65535 UTF-8 bytes");
    }

    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '#') {
        if (i != value.length() - 1 || (i != 0 && value.charAt(i - 1) != '/')) {
          throw malformed("Multi-level wildcard must occupy the final level");
        }
      } else if (ch == '+') {
        if ((i != 0 && value.charAt(i - 1) != '/')
            || (i + 1 != value.length() && value.charAt(i + 1) != '/')) {
          throw malformed("Single-level wildcard must occupy an entire level");
        }
      }
    }
  }

  private static MqttSnException malformed(String message) {
    return new MqttSnException(MqttSnError.MALFORMED_PACKET, message);
  }
}
