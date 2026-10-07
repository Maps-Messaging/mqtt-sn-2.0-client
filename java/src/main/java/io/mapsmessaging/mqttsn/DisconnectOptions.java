package io.mapsmessaging.mqttsn;

public record DisconnectOptions(
    Integer packetIdentifier,
    Integer reasonCode,
    Long sessionExpiryInterval,
    String reasonString) {

  public DisconnectOptions {
    if (packetIdentifier != null && (packetIdentifier < 1 || packetIdentifier > 0xFFFF)) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535 when present");
    }
    if (reasonCode != null && (reasonCode < 0 || reasonCode > 0xFF)) {
      throw new IllegalArgumentException("reasonCode must be 0..255 when present");
    }
    if (sessionExpiryInterval != null
        && (sessionExpiryInterval < 0 || sessionExpiryInterval > 0xFFFF_FFFFL)) {
      throw new IllegalArgumentException("sessionExpiryInterval must be 0..4294967295 when present");
    }
    reasonString = reasonString == null ? "" : reasonString;
    MqttSnUtf8.validate(reasonString);
  }
}
