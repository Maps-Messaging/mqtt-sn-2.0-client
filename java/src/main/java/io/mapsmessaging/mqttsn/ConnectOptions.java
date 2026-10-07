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

import java.util.Objects;

public record ConnectOptions(
    boolean cleanStart,
    boolean allowNetworkAddressChanges,
    boolean allowServerSuggestedValues,
    int packetIdentifier,
    int keepAliveSeconds,
    int maximumPacketSize,
    String clientIdentifier) {

  public ConnectOptions {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    if (keepAliveSeconds < 1 || keepAliveSeconds > 0xFFFF) {
      throw new IllegalArgumentException("keepAliveSeconds must be 1..65535");
    }
    if (maximumPacketSize < 0
        || maximumPacketSize > 0xFFFF
        || (maximumPacketSize != 0 && maximumPacketSize < 10)) {
      throw new IllegalArgumentException("maximumPacketSize must be 0 or 10..65535");
    }
    clientIdentifier = Objects.requireNonNullElse(clientIdentifier, "");
    MqttSnUtf8.validate(clientIdentifier);
  }
}
