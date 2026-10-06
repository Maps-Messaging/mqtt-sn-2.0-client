package io.mapsmessaging.mqttsn;

public record SleepResponse(
    int packetIdentifier,
    Long sleepDurationSeconds,
    Integer reasonCode) {
}
