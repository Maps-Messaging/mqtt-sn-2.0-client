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

import io.mapsmessaging.mqttsn.AuthPacket;
import io.mapsmessaging.mqttsn.ConnAck;
import io.mapsmessaging.mqttsn.MqttSnError;
import io.mapsmessaging.mqttsn.MqttSnException;
import java.util.Objects;

public final class AuthenticationExchange implements AutoCloseable {
  public static final int SUCCESS = 0x00;
  public static final int CONTINUE_AUTHENTICATION = 0x18;
  public static final int REAUTHENTICATE = 0x19;

  private final AuthenticationMechanism mechanism;
  private boolean active;

  public AuthenticationExchange(AuthenticationMechanism mechanism) {
    this.mechanism = Objects.requireNonNull(mechanism, "mechanism");
    if (mechanism.method() == null || mechanism.method().isBlank()) {
      throw new IllegalArgumentException("authentication method is required");
    }
  }

  public String method() {
    return mechanism.method();
  }

  public byte[] initialResponse() {
    active = true;
    byte[] response = mechanism.initialResponse();
    return response == null ? new byte[0] : response.clone();
  }

  public AuthPacket continueAuthentication(AuthPacket serverAuth, int responsePacketIdentifier) {
    Objects.requireNonNull(serverAuth, "serverAuth");
    if (!active) {
      throw state("Authentication exchange is not active");
    }
    if (serverAuth.reasonCode() != CONTINUE_AUTHENTICATION) {
      throw state("Server AUTH must use reason code 0x18 during authentication continuation");
    }
    if (!method().equals(serverAuth.authenticationMethod())) {
      throw state("Authentication Method changed during exchange");
    }

    byte[] response = mechanism.evaluateChallenge(serverAuth.authenticationData());
    return new AuthPacket(
        responsePacketIdentifier,
        CONTINUE_AUTHENTICATION,
        method(),
        response == null ? new byte[0] : response);
  }

  public void acceptConnAck(ConnAck connAck) {
    Objects.requireNonNull(connAck, "connAck");
    if (!active) {
      return;
    }

    if (connAck.reasonCode() == SUCCESS) {
      if (!method().equals(connAck.authenticationMethod())) {
        throw state("Successful CONNACK must retain the Authentication Method");
      }
      byte[] finalData = connAck.authenticationData();
      if (finalData != null && finalData.length != 0) {
        mechanism.evaluateChallenge(finalData);
      }
      if (!mechanism.complete()) {
        throw state("Authentication mechanism did not complete before successful CONNACK");
      }
    }
    active = false;
  }

  public AuthPacket beginReauthentication(int packetIdentifier) {
    if (active) {
      throw state("Authentication exchange is already active");
    }
    mechanism.reset();
    active = true;
    byte[] response = mechanism.initialResponse();
    return new AuthPacket(
        packetIdentifier,
        REAUTHENTICATE,
        method(),
        response == null ? new byte[0] : response);
  }

  public boolean active() {
    return active;
  }

  @Override
  public void close() {
    active = false;
    mechanism.close();
  }

  private static MqttSnException state(String message) {
    return new MqttSnException(MqttSnError.STATE_ERROR, message);
  }
}
