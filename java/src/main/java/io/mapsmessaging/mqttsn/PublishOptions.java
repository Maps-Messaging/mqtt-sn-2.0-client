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

public record PublishOptions(
    QoS qos,
    boolean duplicate,
    boolean retain,
    int packetIdentifier,
    TopicRef topic,
    byte[] payload) {

  public PublishOptions {
    if (qos == null || topic == null) {
      throw new IllegalArgumentException("qos and topic are required");
    }
    payload = payload == null ? new byte[0] : payload.clone();
    if (qos == QoS.AT_MOST_ONCE && packetIdentifier != 0) {
      throw new IllegalArgumentException("QoS 0 PUBLISH must not have a Packet Identifier");
    }
    if (qos != QoS.AT_MOST_ONCE
        && (packetIdentifier < 1 || packetIdentifier > 0xFFFF)) {
      throw new IllegalArgumentException("QoS 1/2 Packet Identifier must be 1..65535");
    }
    if (qos != QoS.EXACTLY_ONCE && duplicate) {
      throw new IllegalArgumentException("DUP is only valid for QoS 2 in MQTT-SN 2.0");
    }
    if (topic.type() == TopicType.NAME) {
      MqttSnTopics.validateName(topic.name());
    }
  }

  @Override
  public byte[] payload() {
    return payload.clone();
  }
}
