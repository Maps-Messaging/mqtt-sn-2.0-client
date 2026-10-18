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
import java.util.Objects;

public record ProtectionEnvelope(
    int scheme,
    int tagLengthCode,
    byte[] senderIdentifier,
    byte[] random,
    byte[] cryptographicMaterial,
    byte[] monotonicCounter,
    byte[] mqttSnPacket) {

  public ProtectionEnvelope {
    if (scheme < 0 || scheme > 0xFF) {
      throw new IllegalArgumentException("scheme must be 0..255");
    }
    if (tagLengthCode < 0 || tagLengthCode > 0x0F) {
      throw new IllegalArgumentException("tagLengthCode must be 0..15");
    }
    senderIdentifier = senderIdentifier == null ? new byte[0] : senderIdentifier.clone();
    random = random == null ? new byte[0] : random.clone();
    cryptographicMaterial =
        cryptographicMaterial == null ? new byte[0] : cryptographicMaterial.clone();
    monotonicCounter = monotonicCounter == null ? new byte[0] : monotonicCounter.clone();
    mqttSnPacket = mqttSnPacket == null ? new byte[0] : mqttSnPacket.clone();
  }

  @Override public byte[] senderIdentifier() { return senderIdentifier.clone(); }
  @Override public byte[] random() { return random.clone(); }
  @Override public byte[] cryptographicMaterial() { return cryptographicMaterial.clone(); }
  @Override public byte[] monotonicCounter() { return monotonicCounter.clone(); }
  @Override public byte[] mqttSnPacket() { return mqttSnPacket.clone(); }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof ProtectionEnvelope envelope
        && scheme == envelope.scheme
        && tagLengthCode == envelope.tagLengthCode
        && Arrays.equals(senderIdentifier, envelope.senderIdentifier)
        && Arrays.equals(random, envelope.random)
        && Arrays.equals(cryptographicMaterial, envelope.cryptographicMaterial)
        && Arrays.equals(monotonicCounter, envelope.monotonicCounter)
        && Arrays.equals(mqttSnPacket, envelope.mqttSnPacket);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(scheme, tagLengthCode);
    result = 31 * result + Arrays.hashCode(senderIdentifier);
    result = 31 * result + Arrays.hashCode(random);
    result = 31 * result + Arrays.hashCode(cryptographicMaterial);
    result = 31 * result + Arrays.hashCode(monotonicCounter);
    return 31 * result + Arrays.hashCode(mqttSnPacket);
  }

  @Override
  public String toString() {
    return "ProtectionEnvelope[scheme=" + scheme
        + ", tagLengthCode=" + tagLengthCode
        + ", senderIdentifier=" + Arrays.toString(senderIdentifier)
        + ", random=" + Arrays.toString(random)
        + ", cryptographicMaterial=" + Arrays.toString(cryptographicMaterial)
        + ", monotonicCounter=" + Arrays.toString(monotonicCounter)
        + ", mqttSnPacket=" + Arrays.toString(mqttSnPacket) + "]";
  }
}
