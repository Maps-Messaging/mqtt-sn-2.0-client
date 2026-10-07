package io.mapsmessaging.mqttsn;

public record AuthPacket(
    int packetIdentifier,
    int reasonCode,
    String authenticationMethod,
    byte[] authenticationData) {

  public AuthPacket {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    if (reasonCode < 0 || reasonCode > 0xFF) {
      throw new IllegalArgumentException("reasonCode must be 0..255");
    }
    authenticationMethod = authenticationMethod == null ? "" : authenticationMethod;
    MqttSnUtf8.validate(authenticationMethod);
    byte[] method = authenticationMethod.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    if (method.length > 0xFF) {
      throw new IllegalArgumentException("authenticationMethod must be at most 255 UTF-8 bytes");
    }
    authenticationData = authenticationData == null ? new byte[0] : authenticationData.clone();
  }

  @Override
  public byte[] authenticationData() {
    return authenticationData.clone();
  }
}
