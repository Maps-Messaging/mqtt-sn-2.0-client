package io.mapsmessaging.mqttsn;

public record ConnectionEncapsulation(String clientIdentifier, byte[] mqttSnPacket) {
  public ConnectionEncapsulation {
    clientIdentifier = clientIdentifier == null ? "" : clientIdentifier;
    MqttSnUtf8.validate(clientIdentifier);
    byte[] clientId = clientIdentifier.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    if (clientId.length > 0xFFFF) {
      throw new IllegalArgumentException("clientIdentifier exceeds 65535 UTF-8 bytes");
    }
    mqttSnPacket = mqttSnPacket == null ? new byte[0] : mqttSnPacket.clone();
  }

  @Override
  public byte[] mqttSnPacket() {
    return mqttSnPacket.clone();
  }
}
