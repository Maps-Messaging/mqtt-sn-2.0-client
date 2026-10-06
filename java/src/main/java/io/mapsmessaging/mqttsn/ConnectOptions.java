package io.mapsmessaging.mqttsn;

import java.util.Objects;

public record ConnectOptions(
    boolean cleanStart,
    boolean allowNetworkAddressChanges,
    boolean allowServerSuggestedValues,
    int packetIdentifier,
    int keepAliveSeconds,
    int maximumPacketSize,
    String clientIdentifier) {

  public ConnectOptions {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    if (keepAliveSeconds < 1 || keepAliveSeconds > 0xFFFF) {
      throw new IllegalArgumentException("keepAliveSeconds must be 1..65535");
    }
    if (maximumPacketSize < 0
        || maximumPacketSize > 0xFFFF
        || (maximumPacketSize != 0 && maximumPacketSize < 10)) {
      throw new IllegalArgumentException("maximumPacketSize must be 0 or 10..65535");
    }
    clientIdentifier = Objects.requireNonNullElse(clientIdentifier, "");
    MqttSnUtf8.validate(clientIdentifier);
  }
}
