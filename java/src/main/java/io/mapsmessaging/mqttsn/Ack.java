package io.mapsmessaging.mqttsn;

public record Ack(int packetIdentifier, Integer reasonCode) {
}
