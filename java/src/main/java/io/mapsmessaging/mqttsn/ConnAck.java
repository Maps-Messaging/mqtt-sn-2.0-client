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

public record ConnAck(
    boolean sessionPresent,
    int packetIdentifier,
    int reasonCode,
    Long sessionExpiryInterval,
    Integer serverKeepAlive,
    String authenticationMethod,
    byte[] authenticationData,
    String assignedClientIdentifier) {

  public ConnAck {
    authenticationData = authenticationData == null ? null : authenticationData.clone();
  }

  @Override
  public byte[] authenticationData() {
    return authenticationData == null ? null : authenticationData.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof ConnAck packet
        && sessionPresent == packet.sessionPresent
        && packetIdentifier == packet.packetIdentifier
        && reasonCode == packet.reasonCode
        && Objects.equals(sessionExpiryInterval, packet.sessionExpiryInterval)
        && Objects.equals(serverKeepAlive, packet.serverKeepAlive)
        && Objects.equals(authenticationMethod, packet.authenticationMethod)
        && Arrays.equals(authenticationData, packet.authenticationData)
        && Objects.equals(assignedClientIdentifier, packet.assignedClientIdentifier);
  }

  @Override
  public int hashCode() {
    return 31 * Objects.hash(
        sessionPresent,
        packetIdentifier,
        reasonCode,
        sessionExpiryInterval,
        serverKeepAlive,
        authenticationMethod,
        assignedClientIdentifier)
        + Arrays.hashCode(authenticationData);
  }

  @Override
  public String toString() {
    return "ConnAck[sessionPresent=" + sessionPresent
        + ", packetIdentifier=" + packetIdentifier
        + ", reasonCode=" + reasonCode
        + ", sessionExpiryInterval=" + sessionExpiryInterval
        + ", serverKeepAlive=" + serverKeepAlive
        + ", authenticationMethod=" + authenticationMethod
        + ", authenticationData=" + Arrays.toString(authenticationData)
        + ", assignedClientIdentifier=" + assignedClientIdentifier + "]";
  }
}
