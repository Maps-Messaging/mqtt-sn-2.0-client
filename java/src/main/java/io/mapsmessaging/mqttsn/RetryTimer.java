package io.mapsmessaging.mqttsn;

/**
 * Caller-clock-driven retry helper for MQTT-SN request packets.
 *
 * <p>CONNECT and AUTH MUST NOT use this timer because CSD01 explicitly
 * prohibits retrying those packets.</p>
 */
public final class RetryTimer {
  private final long retryIntervalMillis;
  private final int maximumRetryCount;
  private boolean active;
  private int retriesSent;
  private long deadlineMillis;

  public RetryTimer(long retryIntervalMillis, int maximumRetryCount) {
    if (retryIntervalMillis <= 0) {
      throw new IllegalArgumentException("retryIntervalMillis must be > 0");
    }
    if (maximumRetryCount < 0) {
      throw new IllegalArgumentException("maximumRetryCount must be >= 0");
    }
    this.retryIntervalMillis = retryIntervalMillis;
    this.maximumRetryCount = maximumRetryCount;
  }

  public void start(long nowMillis) {
    active = true;
    retriesSent = 0;
    deadlineMillis = Math.addExact(nowMillis, retryIntervalMillis);
  }

  public void cancel() {
    active = false;
    retriesSent = 0;
  }

  public boolean active() {
    return active;
  }

  public int retriesSent() {
    return retriesSent;
  }

  public RetryAction poll(long nowMillis) {
    if (!active || nowMillis < deadlineMillis) {
      return RetryAction.NONE;
    }

    if (retriesSent < maximumRetryCount) {
      retriesSent++;
      deadlineMillis = Math.addExact(nowMillis, retryIntervalMillis);
      return RetryAction.RETRANSMIT;
    }

    active = false;
    return RetryAction.DELETE_CONNECTION;
  }
}
