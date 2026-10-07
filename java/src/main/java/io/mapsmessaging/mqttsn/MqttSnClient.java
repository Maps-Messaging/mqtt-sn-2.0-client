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
import java.util.Objects;
import java.util.function.Consumer;

public final class MqttSnClient {

  /**
   * Processes every complete MQTT-SN packet in the supplied buffer.
   *
   * The method owns no transport and retains no reference to the input.
   * It returns the number of bytes consumed so a stream-oriented transport
   * can retain an incomplete trailing packet.
   */
  public int accept(ByteBuffer input, Consumer<DecodedPacket> handler) {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(handler, "handler");

    int consumed = 0;
    while (consumed < input.remaining()) {
      ByteBuffer view = input.asReadOnlyBuffer();
      view.position(input.position() + consumed);
      view = view.slice();

      final DecodedPacket packet;
      try {
        packet = MqttSnCodec.decode(view);
      } catch (MqttSnException ex) {
        if (ex.error() == MqttSnError.NEED_MORE) {
          return consumed;
        }
        throw ex;
      }

      handler.accept(packet);
      consumed += packet.packetLength();
    }
    return consumed;
  }

  public byte[] encode(PacketType type, byte[] body) {
    return MqttSnCodec.encode(type, body);
  }
}
