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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.mqttsn.AuthPacket;
import io.mapsmessaging.mqttsn.ConnAck;
import io.mapsmessaging.mqttsn.MqttSnException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

/**
 * MQTT-SN 2.0 CSD01 MQTT-SN-4.11.1-2/-3/-5 and
 * MQTT-SN-4.11.1.1-1.
 */
class AuthenticationExchangeTest {

  @Test
  void genericMechanismHandlesContinuationAndSuccessfulConnAck() {
    TestMechanism mechanism = new TestMechanism();
    AuthenticationExchange exchange = new AuthenticationExchange(mechanism);

    assertArrayEquals(new byte[] {0x01}, exchange.initialResponse());
    assertTrue(exchange.active());

    AuthPacket response = exchange.continueAuthentication(
        new AuthPacket(0x1001, 0x18, "TEST", new byte[] {0x10}),
        0x1002);

    assertEquals(0x18, response.reasonCode());
    assertEquals("TEST", response.authenticationMethod());
    assertArrayEquals(new byte[] {0x02}, response.authenticationData());

    exchange.acceptConnAck(new ConnAck(
        false, 0x1002, 0, null, null,
        "TEST", new byte[] {0x7F}, ""));

    assertTrue(mechanism.complete());
    assertFalse(exchange.active());
  }

  @Test
  void methodCannotChangeDuringExchange() {
    AuthenticationExchange exchange =
        new AuthenticationExchange(new TestMechanism());
    exchange.initialResponse();

    assertThrows(
        MqttSnException.class,
        () -> exchange.continueAuthentication(
            new AuthPacket(1, 0x18, "OTHER", new byte[0]),
            2));
  }

  @Test
  void reauthenticationUsesReasonCode19AndResetsMechanism() {
    TestMechanism mechanism = new TestMechanism();
    AuthenticationExchange exchange = new AuthenticationExchange(mechanism);
    exchange.initialResponse();
    exchange.acceptConnAck(new ConnAck(
        false, 1, 0, null, null,
        "TEST", new byte[] {0x7F}, ""));

    AuthPacket reauth = exchange.beginReauthentication(0x2222);

    assertEquals(0x19, reauth.reasonCode());
    assertEquals("TEST", reauth.authenticationMethod());
    assertArrayEquals(new byte[] {0x01}, reauth.authenticationData());
    assertEquals(1, mechanism.resetCount);
  }

  @Test
  void saslAdapterUsesMechanismNameAndChallengeBytes() {
    AtomicInteger created = new AtomicInteger();
    SaslAuthenticationMechanism mechanism =
        new SaslAuthenticationMechanism(() -> {
          created.incrementAndGet();
          return new StubSaslClient();
        });

    AuthenticationExchange exchange = new AuthenticationExchange(mechanism);
    assertArrayEquals(new byte[] {0x11}, exchange.initialResponse());

    AuthPacket response = exchange.continueAuthentication(
        new AuthPacket(1, 0x18, "TEST-SASL", new byte[] {0x22}),
        2);
    assertArrayEquals(new byte[] {0x33}, response.authenticationData());

    exchange.acceptConnAck(new ConnAck(
        false, 2, 0, null, null,
        "TEST-SASL", new byte[] {0x44}, ""));
    assertFalse(exchange.active());

    exchange.beginReauthentication(3);
    assertEquals(2, created.get());
  }

  private static final class TestMechanism implements AuthenticationMechanism {
    private boolean complete;
    private int resetCount;

    @Override
    public String method() {
      return "TEST";
    }

    @Override
    public byte[] initialResponse() {
      return new byte[] {0x01};
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) {
      if (challenge.length == 1 && challenge[0] == 0x7F) {
        complete = true;
        return new byte[0];
      }
      return new byte[] {0x02};
    }

    @Override
    public boolean complete() {
      return complete;
    }

    @Override
    public void reset() {
      complete = false;
      resetCount++;
    }
  }

  private static final class StubSaslClient implements SaslClient {
    private boolean complete;

    @Override
    public String getMechanismName() {
      return "TEST-SASL";
    }

    @Override
    public boolean hasInitialResponse() {
      return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) {
      if (challenge.length == 0) {
        return new byte[] {0x11};
      }
      if (challenge.length == 1 && challenge[0] == 0x22) {
        return new byte[] {0x33};
      }
      if (challenge.length == 1 && challenge[0] == 0x44) {
        complete = true;
        return new byte[0];
      }
      throw new IllegalArgumentException("unexpected challenge");
    }

    @Override
    public boolean isComplete() {
      return complete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
      throw new SaslException("not used");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
      throw new SaslException("not used");
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
      return null;
    }

    @Override
    public void dispose() {
    }
  }
}
