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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

/**
 * Additional MQTT-SN 2.0 CSD01 authentication state and mechanism coverage.
 *
 * <p>Covers client-side behavior around MQTT-SN-4.11.1-2/-3/-5/-7 and
 * MQTT-SN-4.11.1.1-1/-2 without changing the mechanism-agnostic protocol API.</p>
 */
class AuthenticationEdgeCaseTest {

  @Test
  void rejectsNullAndBlankAuthenticationMethods() {
    assertThrows(
        NullPointerException.class,
        () -> new AuthenticationExchange(null));

    AuthenticationMechanism blank = new FixedMechanism(" ", null, true);
    assertThrows(
        IllegalArgumentException.class,
        () -> new AuthenticationExchange(blank));
  }

  @Test
  void nullInitialResponseIsExposedAsEmptyData() {
    AuthenticationExchange exchange =
        new AuthenticationExchange(new FixedMechanism("TEST", null, true));

    assertArrayEquals(new byte[0], exchange.initialResponse());
    assertTrue(exchange.active());
  }

  @Test
  void continuationRequiresActiveExchangeAndContinueReasonCode() {
    AuthenticationExchange exchange =
        new AuthenticationExchange(new FixedMechanism("TEST", new byte[0], true));
    AuthPacket continuation =
        new AuthPacket(1, AuthenticationExchange.CONTINUE_AUTHENTICATION, "TEST", new byte[0]);

    assertThrows(
        MqttSnException.class,
        () -> exchange.continueAuthentication(continuation, 2));

    exchange.initialResponse();
    AuthPacket wrongReason =
        new AuthPacket(1, AuthenticationExchange.REAUTHENTICATE, "TEST", new byte[0]);
    assertThrows(
        MqttSnException.class,
        () -> exchange.continueAuthentication(wrongReason, 2));
  }

  @Test
  void successfulConnAckRequiresSameMethodAndCompletedMechanism() {
    AuthenticationExchange changedMethod =
        new AuthenticationExchange(new FixedMechanism("TEST", new byte[0], true));
    changedMethod.initialResponse();
    ConnAck wrongMethod =
        new ConnAck(false, 1, 0, null, null, "OTHER", null, "");

    assertThrows(
        MqttSnException.class,
        () -> changedMethod.acceptConnAck(wrongMethod));

    AuthenticationExchange incomplete =
        new AuthenticationExchange(new FixedMechanism("TEST", new byte[0], false));
    incomplete.initialResponse();
    ConnAck success =
        new ConnAck(false, 1, 0, null, null, "TEST", null, "");

    assertThrows(
        MqttSnException.class,
        () -> incomplete.acceptConnAck(success));
  }

  @Test
  void rejectedConnAckEndsExchangeWithoutRequiringCompletion() {
    AuthenticationExchange exchange =
        new AuthenticationExchange(new FixedMechanism("TEST", new byte[0], false));
    exchange.initialResponse();

    exchange.acceptConnAck(
        new ConnAck(false, 1, 0x87, null, null, null, null, ""));

    assertFalse(exchange.active());
  }

  @Test
  void inactiveConnAckIsIgnoredAndReauthenticationCannotNest() {
    AuthenticationExchange exchange =
        new AuthenticationExchange(new FixedMechanism("TEST", new byte[0], true));

    exchange.acceptConnAck(
        new ConnAck(false, 1, 0, null, null, "TEST", null, ""));
    assertFalse(exchange.active());

    exchange.initialResponse();
    assertThrows(
        MqttSnException.class,
        () -> exchange.beginReauthentication(2));
  }

  @Test
  void closeEndsExchangeAndDelegatesToMechanism() {
    AtomicBoolean closed = new AtomicBoolean();
    AuthenticationMechanism mechanism = new AuthenticationMechanism() {
      @Override
      public String method() {
        return "TEST";
      }

      @Override
      public byte[] initialResponse() {
        return new byte[0];
      }

      @Override
      public byte[] evaluateChallenge(byte[] challenge) {
        return new byte[0];
      }

      @Override
      public boolean complete() {
        return true;
      }

      @Override
      public void close() {
        closed.set(true);
      }
    };

    AuthenticationExchange exchange = new AuthenticationExchange(mechanism);
    exchange.initialResponse();
    exchange.close();

    assertFalse(exchange.active());
    assertTrue(closed.get());
  }

  @Test
  void authenticationMechanismDefaultsAreNoOps() {
    AuthenticationMechanism mechanism =
        new FixedMechanism("TEST", new byte[0], true);

    mechanism.reset();
    mechanism.close();

    assertTrue(mechanism.complete());
  }

  @Test
  void saslWithoutInitialResponseProducesEmptyResponseAndOnlyOnce() {
    SaslAuthenticationMechanism mechanism =
        new SaslAuthenticationMechanism(new ConfigurableSaslClient(false));

    assertArrayEquals(new byte[0], mechanism.initialResponse());
    assertArrayEquals(new byte[0], mechanism.initialResponse());
    assertEquals("TEST-SASL", mechanism.method());
    assertFalse(mechanism.complete());
  }

  @Test
  void saslNormalizesNullChallengeAndNullResponse() {
    ConfigurableSaslClient client = new ConfigurableSaslClient(true);
    client.returnNull = true;
    SaslAuthenticationMechanism mechanism =
        new SaslAuthenticationMechanism(client);

    assertArrayEquals(new byte[0], mechanism.evaluateChallenge(null));
  }

  @Test
  void oneShotSaslClientCannotBeResetForReauthentication() {
    SaslAuthenticationMechanism mechanism =
        new SaslAuthenticationMechanism(new ConfigurableSaslClient(true));

    assertThrows(
        IllegalStateException.class,
        mechanism::reset);
  }

  @Test
  void saslFactoryMustProduceAClient() {
    Supplier<SaslClient> nullFactory = () -> null;

    assertThrows(
        NullPointerException.class,
        () -> new SaslAuthenticationMechanism(nullFactory));
  }

  @Test
  void saslEvaluationAndDisposeFailuresAreReported() {
    ConfigurableSaslClient evaluationFailure = new ConfigurableSaslClient(true);
    evaluationFailure.failEvaluate = true;
    SaslAuthenticationMechanism evaluating =
        new SaslAuthenticationMechanism(evaluationFailure);

    assertThrows(
        IllegalStateException.class,
        () -> evaluating.evaluateChallenge(new byte[] {1}));

    ConfigurableSaslClient disposeFailure = new ConfigurableSaslClient(true);
    disposeFailure.failDispose = true;
    SaslAuthenticationMechanism disposing =
        new SaslAuthenticationMechanism(disposeFailure);

    assertThrows(
        IllegalStateException.class,
        disposing::close);
  }

  private static final class FixedMechanism implements AuthenticationMechanism {
    private final String method;
    private final byte[] initialResponse;
    private final boolean complete;

    private FixedMechanism(String method, byte[] initialResponse, boolean complete) {
      this.method = method;
      this.initialResponse = initialResponse;
      this.complete = complete;
    }

    @Override
    public String method() {
      return method;
    }

    @Override
    public byte[] initialResponse() {
      return initialResponse;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) {
      return null;
    }

    @Override
    public boolean complete() {
      return complete;
    }
  }

  private static final class ConfigurableSaslClient implements SaslClient {
    private final boolean hasInitialResponse;
    private boolean complete;
    private boolean returnNull;
    private boolean failEvaluate;
    private boolean failDispose;

    private ConfigurableSaslClient(boolean hasInitialResponse) {
      this.hasInitialResponse = hasInitialResponse;
    }

    @Override
    public String getMechanismName() {
      return "TEST-SASL";
    }

    @Override
    public boolean hasInitialResponse() {
      return hasInitialResponse;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
      if (failEvaluate) {
        throw new SaslException("expected");
      }
      complete = true;
      return returnNull ? null : challenge.clone();
    }

    @Override
    public boolean isComplete() {
      return complete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
      throw new UnsupportedOperationException();
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
      return null;
    }

    @Override
    public void dispose() throws SaslException {
      if (failDispose) {
        throw new SaslException("expected");
      }
    }
  }
}
