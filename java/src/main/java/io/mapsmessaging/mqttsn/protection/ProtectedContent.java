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

package io.mapsmessaging.mqttsn.protection;

import java.util.Arrays;

public record ProtectedContent(byte[] protectedPacket, byte[] authenticationTag) {
  public ProtectedContent {
    protectedPacket = protectedPacket == null ? new byte[0] : protectedPacket.clone();
    authenticationTag = authenticationTag == null ? new byte[0] : authenticationTag.clone();
  }

  @Override
  public byte[] protectedPacket() {
    return protectedPacket.clone();
  }

  @Override
  public byte[] authenticationTag() {
    return authenticationTag.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof ProtectedContent content
        && Arrays.equals(protectedPacket, content.protectedPacket)
        && Arrays.equals(authenticationTag, content.authenticationTag);
  }

  @Override
  public int hashCode() {
    return 31 * Arrays.hashCode(protectedPacket) + Arrays.hashCode(authenticationTag);
  }

  @Override
  public String toString() {
    return "ProtectedContent[protectedPacket=" + Arrays.toString(protectedPacket)
        + ", authenticationTag=" + Arrays.toString(authenticationTag) + "]";
  }
}
