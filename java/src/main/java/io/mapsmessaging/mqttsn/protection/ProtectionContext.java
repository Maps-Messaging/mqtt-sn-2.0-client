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

public record ProtectionContext(
    int scheme,
    int tagLengthCode,
    byte[] senderIdentifier,
    byte[] random,
    byte[] cryptographicMaterial,
    byte[] monotonicCounter,
    byte[] authenticatedPrefix) {

  public ProtectionContext {
    senderIdentifier = senderIdentifier.clone();
    random = random.clone();
    cryptographicMaterial = cryptographicMaterial.clone();
    monotonicCounter = monotonicCounter.clone();
    authenticatedPrefix = authenticatedPrefix.clone();
  }

  @Override public byte[] senderIdentifier() { return senderIdentifier.clone(); }
  @Override public byte[] random() { return random.clone(); }
  @Override public byte[] cryptographicMaterial() { return cryptographicMaterial.clone(); }
  @Override public byte[] monotonicCounter() { return monotonicCounter.clone(); }
  @Override public byte[] authenticatedPrefix() { return authenticatedPrefix.clone(); }
}
