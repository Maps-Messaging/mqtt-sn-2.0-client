package io.mapsmessaging.mqttsn;

public record PingResp(int packetIdentifier, Integer applicationMessagesRemaining) {
}
