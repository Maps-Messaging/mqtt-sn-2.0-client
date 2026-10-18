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

public record ForwarderEncapsulation(byte[] clientAddressingInformation, byte[] mqttSnPacket) {
  public ForwarderEncapsulation {
    clientAddressingInformation =
        clientAddressingInformation == null ? new byte[0] : clientAddressingInformation.clone();
    if (clientAddressingInformation.length > 0xFF) {
      throw new IllegalArgumentException("clientAddressingInformation exceeds 255 bytes");
    }
    mqttSnPacket = mqttSnPacket == null ? new byte[0] : mqttSnPacket.clone();
  }

  @Override
  public byte[] clientAddressingInformation() {
    return clientAddressingInformation.clone();
  }

  @Override
  public byte[] mqttSnPacket() {
    return mqttSnPacket.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof ForwarderEncapsulation packet
        && Arrays.equals(clientAddressingInformation, packet.clientAddressingInformation)
        && Arrays.equals(mqttSnPacket, packet.mqttSnPacket);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(clientAddressingInformation)
        + Arrays.hashCode(mqttSnPacket);
  }

  @Override
  public String toString() {
    return "ForwarderEncapsulation[clientAddressingInformation="
        + Arrays.toString(clientAddressingInformation)
        + ", mqttSnPacket=" + Arrays.toString(mqttSnPacket) + "]";
  }
}
