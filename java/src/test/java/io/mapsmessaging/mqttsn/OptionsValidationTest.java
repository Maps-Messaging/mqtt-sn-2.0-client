package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class OptionsValidationTest {

  @Test
  void connectOptionsAcceptBoundaryValues() {
    ConnectOptions minimum = new ConnectOptions(true, false, false, 1, 1, 0, null);
    ConnectOptions maximum = new ConnectOptions(false, true, true, 0xFFFF, 0xFFFF, 0xFFFF, "client");

    assertEquals("", minimum.clientIdentifier());
    assertEquals(0xFFFF, maximum.packetIdentifier());
  }

  @Test
  void connectOptionsRejectInvalidBoundaries() {
    assertThrows(IllegalArgumentException.class,
        () -> new ConnectOptions(true, false, false, 0, 60, 0, "c"));
    assertThrows(IllegalArgumentException.class,
        () -> new ConnectOptions(true, false, false, 1, 0, 0, "c"));
    assertThrows(IllegalArgumentException.class,
        () -> new ConnectOptions(true, false, false, 1, 60, 9, "c"));
    assertThrows(IllegalArgumentException.class,
        () -> new ConnectOptions(true, false, false, 1, 60, 0x1_0000, "c"));
  }

  @Test
  void topicReferencesEnforceAliasAndNameRules() {
    assertEquals(1, TopicRef.sessionAlias(1).alias());
    assertEquals(0xFFFF, TopicRef.predefinedAlias(0xFFFF).alias());
    assertThrows(IllegalArgumentException.class, () -> TopicRef.sessionAlias(0));
    assertThrows(IllegalArgumentException.class, () -> TopicRef.predefinedAlias(0x1_0000));
    assertThrows(IllegalArgumentException.class,
        () -> new TopicRef(TopicType.NAME, 1, "a/b"));
    assertThrows(IllegalArgumentException.class,
        () -> new TopicRef(TopicType.SESSION_ALIAS, 1, "a/b"));
  }

  @Test
  void publishOptionsEnforcePacketIdentifierAndDupRules() {
    TopicRef topic = TopicRef.name("a/b");

    assertThrows(IllegalArgumentException.class,
        () -> new PublishOptions(QoS.AT_MOST_ONCE, false, false, 1, topic, null));
    assertThrows(IllegalArgumentException.class,
        () -> new PublishOptions(QoS.AT_LEAST_ONCE, false, false, 0, topic, null));
    assertThrows(IllegalArgumentException.class,
        () -> new PublishOptions(QoS.AT_LEAST_ONCE, true, false, 1, topic, null));

    PublishOptions qos2 = new PublishOptions(
        QoS.EXACTLY_ONCE, true, true, 0xFFFF, topic, null);
    assertEquals(0xFFFF, qos2.packetIdentifier());
  }

  @Test
  void publishPayloadIsDefensivelyCopied() {
    byte[] source = {1, 2, 3};
    PublishOptions options = new PublishOptions(
        QoS.AT_MOST_ONCE, false, false, 0, TopicRef.name("a/b"), source);

    source[0] = 9;
    byte[] first = options.payload();
    assertArrayEquals(new byte[] {1, 2, 3}, first);
    first[1] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, options.payload());
  }

  @Test
  void subscribeOptionsValidateRetainHandlingAndPacketIdentifier() {
    TopicRef filter = TopicRef.filter("sensors/+");

    assertThrows(IllegalArgumentException.class,
        () -> new SubscribeOptions(0, filter, 0, false, QoS.AT_MOST_ONCE, false));
    assertThrows(IllegalArgumentException.class,
        () -> new SubscribeOptions(1, filter, -1, false, QoS.AT_MOST_ONCE, false));
    assertThrows(IllegalArgumentException.class,
        () -> new SubscribeOptions(1, filter, 3, false, QoS.AT_MOST_ONCE, false));
  }

  @Test
  void sleepRequestValidatesUnsignedRanges() {
    new SleepRequest(1, false, 1);
    new SleepRequest(0xFFFF, true, 0xFFFF_FFFFL);

    assertThrows(IllegalArgumentException.class, () -> new SleepRequest(0, false, 1));
    assertThrows(IllegalArgumentException.class, () -> new SleepRequest(1, false, 0));
    assertThrows(IllegalArgumentException.class,
        () -> new SleepRequest(1, false, 0x1_0000_0000L));
  }
}
