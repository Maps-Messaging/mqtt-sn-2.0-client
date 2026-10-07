package io.mapsmessaging.mqttsn;

/**
 * Caller-clock-driven client Keep Alive helper.
 *
 * <p>Any outbound MQTT-SN Control Packet resets the timer. If no packet has
 * been sent for the Keep Alive interval, the caller should send PINGREQ.</p>
 */
public final class KeepAliveTimer {
  private final long keepAliveMillis;
  private boolean active;
  private long deadlineMillis;

  public KeepAliveTimer(long keepAliveMillis) {
    if (keepAliveMillis <= 0) {
      throw new IllegalArgumentException("keepAliveMillis must be > 0");
    }
    this.keepAliveMillis = keepAliveMillis;
  }

  public void start(long nowMillis) {
    active = true;
    deadlineMillis = Math.addExact(nowMillis, keepAliveMillis);
  }

  public void outboundActivity(long nowMillis) {
    if (active) {
      deadlineMillis = Math.addExact(nowMillis, keepAliveMillis);
    }
  }

  public void stop() {
    active = false;
  }

  public KeepAliveAction poll(long nowMillis) {
    if (!active || nowMillis < deadlineMillis) {
      return KeepAliveAction.NONE;
    }
    deadlineMillis = Math.addExact(nowMillis, keepAliveMillis);
    return KeepAliveAction.SEND_PINGREQ;
  }
}
