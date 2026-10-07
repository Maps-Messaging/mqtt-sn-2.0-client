package io.mapsmessaging.mqttsn;

public record DisconnectPacket(
    Integer packetIdentifier,
    Integer reasonCode,
    Long sessionExpiryInterval,
    String reasonString) {
}
