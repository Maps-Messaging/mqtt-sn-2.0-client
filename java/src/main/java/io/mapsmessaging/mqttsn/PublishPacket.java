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

import java.util.Arrays;
import java.util.Objects;

public record PublishPacket(
    QoS qos,
    boolean duplicate,
    boolean retain,
    int packetIdentifier,
    TopicRef topic,
    byte[] payload) {

  public PublishPacket {
    payload = payload.clone();
  }

  @Override
  public byte[] payload() {
    return payload.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof PublishPacket packet
        && duplicate == packet.duplicate
        && retain == packet.retain
        && packetIdentifier == packet.packetIdentifier
        && qos == packet.qos
        && Objects.equals(topic, packet.topic)
        && Arrays.equals(payload, packet.payload);
  }

  @Override
  public int hashCode() {
    return 31 * Objects.hash(qos, duplicate, retain, packetIdentifier, topic)
        + Arrays.hashCode(payload);
  }

  @Override
  public String toString() {
    return "PublishPacket[qos=" + qos
        + ", duplicate=" + duplicate
        + ", retain=" + retain
        + ", packetIdentifier=" + packetIdentifier
        + ", topic=" + topic
        + ", payload=" + Arrays.toString(payload) + "]";
  }
}
