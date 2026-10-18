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

public record GwInfoPacket(int gatewayIdentifier, byte[] gatewayAddress) {
  public GwInfoPacket {
    if (gatewayIdentifier < 0 || gatewayIdentifier > 0xFF) {
      throw new IllegalArgumentException("gatewayIdentifier must be 0..255");
    }
    gatewayAddress = gatewayAddress == null ? new byte[0] : gatewayAddress.clone();
  }

  @Override
  public byte[] gatewayAddress() {
    return gatewayAddress.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof GwInfoPacket packet
        && gatewayIdentifier == packet.gatewayIdentifier
        && Arrays.equals(gatewayAddress, packet.gatewayAddress);
  }

  @Override
  public int hashCode() {
    return 31 * Objects.hash(gatewayIdentifier) + Arrays.hashCode(gatewayAddress);
  }

  @Override
  public String toString() {
    return "GwInfoPacket[gatewayIdentifier=" + gatewayIdentifier
        + ", gatewayAddress=" + Arrays.toString(gatewayAddress) + "]";
  }
}
