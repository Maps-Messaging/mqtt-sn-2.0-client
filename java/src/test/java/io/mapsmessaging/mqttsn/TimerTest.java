package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * MQTT-SN 2.0 CSD01: §4.4.2 Unacknowledged Packets and §3.1.6 Keep Alive.
 * Covers MQTT-SN-4.4.2-1/-2/-5/-7 and MQTT-SN-3.1.6-1/-3.
 */
class TimerTest {

  @Test
  void retryTimerRetransmitsThenDeletesConnection() {
    RetryTimer timer = new RetryTimer(1000, 2);
    timer.start(100);

    assertEquals(RetryAction.NONE, timer.poll(1099));
    assertEquals(RetryAction.RETRANSMIT, timer.poll(1100));
    assertEquals(1, timer.retriesSent());
    assertEquals(RetryAction.RETRANSMIT, timer.poll(2100));
    assertEquals(2, timer.retriesSent());
    assertEquals(RetryAction.DELETE_CONNECTION, timer.poll(3100));
    assertFalse(timer.active());
  }

  @Test
  void retryTimerCanBeCancelled() {
    RetryTimer timer = new RetryTimer(1000, 1);
    timer.start(0);
    timer.cancel();

    assertFalse(timer.active());
    assertEquals(RetryAction.NONE, timer.poll(5000));
  }

  @Test
  void keepAliveRequestsPingAfterIdleInterval() {
    KeepAliveTimer timer = new KeepAliveTimer(60_000);
    timer.start(1000);

    assertEquals(KeepAliveAction.NONE, timer.poll(60_999));
    assertEquals(KeepAliveAction.SEND_PINGREQ, timer.poll(61_000));
    assertTrue(timer.active());
    assertEquals(KeepAliveAction.NONE, timer.poll(120_999));
    assertEquals(KeepAliveAction.SEND_PINGREQ, timer.poll(121_000));
  }

  @Test
  void outboundActivityResetsKeepAliveDeadline() {
    KeepAliveTimer timer = new KeepAliveTimer(1000);
    timer.start(0);
    timer.outboundActivity(900);

    assertEquals(KeepAliveAction.NONE, timer.poll(1000));
    assertEquals(KeepAliveAction.SEND_PINGREQ, timer.poll(1900));
  }
}
