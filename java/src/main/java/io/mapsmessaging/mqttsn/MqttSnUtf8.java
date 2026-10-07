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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

final class MqttSnUtf8 {
  private MqttSnUtf8() {
  }

  static void validate(String value) {
    if (value.indexOf('\0') >= 0) {
      throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "MQTT-SN UTF-8 must not contain U+0000");
    }
    try {
      StandardCharsets.UTF_8.newEncoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .encode(CharBuffer.wrap(value));
    } catch (CharacterCodingException ex) {
      throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "Invalid MQTT-SN UTF-8 string");
    }
  }

  static String decode(ByteBuffer value) {
    try {
      String decoded = StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(value.asReadOnlyBuffer())
          .toString();
      validate(decoded);
      return decoded;
    } catch (CharacterCodingException ex) {
      throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "Invalid MQTT-SN UTF-8 bytes");
    }
  }
}
