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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.mqttsn.protection.ProtectedContent;
import io.mapsmessaging.mqttsn.protection.ProtectionContext;
import io.mapsmessaging.mqttsn.protection.ProtectionEnvelope;
import org.junit.jupiter.api.Test;

class ArrayRecordEqualityTest {

  @Test
  void packetModelsUseByteContentForEqualityAndHashCodes() {
    assertEquivalent(
        new AuthPacket(1, 0x18, "TEST", new byte[] {1, 2}),
        new AuthPacket(1, 0x18, "TEST", new byte[] {1, 2}));

    assertEquivalent(
        new ConnAck(false, 1, 0, null, null, "TEST", new byte[] {3}, ""),
        new ConnAck(false, 1, 0, null, null, "TEST", new byte[] {3}, ""));

    assertEquivalent(
        new ConnectionEncapsulation("client", new byte[] {2, 0x0C}),
        new ConnectionEncapsulation("client", new byte[] {2, 0x0C}));

    assertEquivalent(
        new ForwarderEncapsulation(new byte[] {1}, new byte[] {2, 0x0C}),
        new ForwarderEncapsulation(new byte[] {1}, new byte[] {2, 0x0C}));

    assertEquivalent(
        new GwInfoPacket(1, new byte[] {10, 20}),
        new GwInfoPacket(1, new byte[] {10, 20}));

    assertEquivalent(
        new PubWosPacket(false, TopicRef.name("a/b"), new byte[] {1}),
        new PubWosPacket(false, TopicRef.name("a/b"), new byte[] {1}));

    assertEquivalent(
        new PublishOptions(
            QoS.AT_MOST_ONCE, false, false, 0, TopicRef.name("a/b"), new byte[] {1}),
        new PublishOptions(
            QoS.AT_MOST_ONCE, false, false, 0, TopicRef.name("a/b"), new byte[] {1}));

    assertEquivalent(
        new PublishPacket(
            QoS.AT_MOST_ONCE, false, false, 0, TopicRef.name("a/b"), new byte[] {1}),
        new PublishPacket(
            QoS.AT_MOST_ONCE, false, false, 0, TopicRef.name("a/b"), new byte[] {1}));

    assertEquivalent(
        new SearchGwPacket(new byte[] {1, 2, 3}),
        new SearchGwPacket(new byte[] {1, 2, 3}));
  }

  @Test
  void protectionModelsUseByteContentForEqualityAndHashCodes() {
    assertEquivalent(
        new ProtectedContent(new byte[] {1}, new byte[] {2}),
        new ProtectedContent(new byte[] {1}, new byte[] {2}));

    assertEquivalent(
        new ProtectionContext(
            0x46,
            1,
            new byte[8],
            new byte[4],
            new byte[] {1, 2},
            new byte[] {3, 4},
            new byte[] {5, 6}),
        new ProtectionContext(
            0x46,
            1,
            new byte[8],
            new byte[4],
            new byte[] {1, 2},
            new byte[] {3, 4},
            new byte[] {5, 6}));

    assertEquivalent(
        new ProtectionEnvelope(
            0x46,
            1,
            new byte[8],
            new byte[4],
            new byte[] {1, 2},
            new byte[] {3, 4},
            new byte[] {2, 0x0C}),
        new ProtectionEnvelope(
            0x46,
            1,
            new byte[8],
            new byte[4],
            new byte[] {1, 2},
            new byte[] {3, 4},
            new byte[] {2, 0x0C}));
  }

  @Test
  void differingByteContentIsNotEqual() {
    assertNotEquals(
        new SearchGwPacket(new byte[] {1}),
        new SearchGwPacket(new byte[] {2}));
  }

  private static void assertEquivalent(Object first, Object second) {
    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
    assertTrue(first.toString().contains("["));
  }
}
