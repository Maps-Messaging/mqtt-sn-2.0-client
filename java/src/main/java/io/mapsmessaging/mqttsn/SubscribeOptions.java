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

public record SubscribeOptions(
    int packetIdentifier,
    TopicRef topic,
    int retainHandling,
    boolean retainAsPublished,
    QoS maximumQos,
    boolean noLocal) {

  public SubscribeOptions {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    if (topic == null || maximumQos == null) {
      throw new IllegalArgumentException("topic and maximumQos are required");
    }
    if (retainHandling < 0 || retainHandling > 2) {
      throw new IllegalArgumentException("retainHandling must be 0..2");
    }
    if (topic.type() == TopicType.NAME) {
      MqttSnTopics.validateFilter(topic.name());
    }
  }
}
