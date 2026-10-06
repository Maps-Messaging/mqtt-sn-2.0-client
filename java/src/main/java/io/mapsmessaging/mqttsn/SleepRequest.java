package io.mapsmessaging.mqttsn;

public record SleepRequest(
    int packetIdentifier,
    boolean retainTopicAliases,
    long sleepDurationSeconds) {

  public SleepRequest {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    if (sleepDurationSeconds < 1 || sleepDurationSeconds > 0xFFFF_FFFFL) {
      throw new IllegalArgumentException("sleepDurationSeconds must be 1..4294967295");
    }
  }
}
