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

public record PubWosPacket(boolean retain, TopicRef topic, byte[] payload) {
  public PubWosPacket {
    if (topic == null) {
      throw new IllegalArgumentException("topic is required");
    }
    if (topic.type() == TopicType.SESSION_ALIAS) {
      throw new IllegalArgumentException("PUBWOS does not allow Session Topic Alias");
    }
    if (topic.type() == TopicType.NAME) {
      MqttSnTopics.validateName(topic.name());
    }
    payload = payload == null ? new byte[0] : payload.clone();
  }

  @Override
  public byte[] payload() {
    return payload.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof PubWosPacket packet
        && retain == packet.retain
        && Objects.equals(topic, packet.topic)
        && Arrays.equals(payload, packet.payload);
  }

  @Override
  public int hashCode() {
    return 31 * Objects.hash(retain, topic) + Arrays.hashCode(payload);
  }

  @Override
  public String toString() {
    return "PubWosPacket[retain=" + retain
        + ", topic=" + topic
        + ", payload=" + Arrays.toString(payload) + "]";
  }
}
