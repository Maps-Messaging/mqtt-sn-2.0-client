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

package io.mapsmessaging.mqttsn.auth;

import java.util.Objects;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public final class SaslAuthenticationMechanism implements AuthenticationMechanism {
  private final SaslClient saslClient;
  private boolean initialResponseGenerated;

  public SaslAuthenticationMechanism(SaslClient saslClient) {
    this.saslClient = Objects.requireNonNull(saslClient, "saslClient");
  }

  @Override
  public String method() {
    return saslClient.getMechanismName();
  }

  @Override
  public byte[] initialResponse() {
    if (initialResponseGenerated) {
      return new byte[0];
    }
    initialResponseGenerated = true;
    if (!saslClient.hasInitialResponse()) {
      return new byte[0];
    }
    return evaluate(new byte[0]);
  }

  @Override
  public byte[] evaluateChallenge(byte[] challenge) {
    return evaluate(challenge == null ? new byte[0] : challenge);
  }

  @Override
  public boolean complete() {
    return saslClient.isComplete();
  }

  @Override
  public void close() {
    try {
      saslClient.dispose();
    } catch (SaslException ex) {
      throw new IllegalStateException("Unable to dispose SASL client", ex);
    }
  }

  private byte[] evaluate(byte[] challenge) {
    try {
      byte[] response = saslClient.evaluateChallenge(challenge);
      return response == null ? new byte[0] : response;
    } catch (SaslException ex) {
      throw new IllegalStateException("SASL authentication failed", ex);
    }
  }
}
