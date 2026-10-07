package io.mapsmessaging.mqttsn;

public record ForwarderEncapsulation(byte[] clientAddressingInformation, byte[] mqttSnPacket) {
  public ForwarderEncapsulation {
    clientAddressingInformation =
        clientAddressingInformation == null ? new byte[0] : clientAddressingInformation.clone();
    if (clientAddressingInformation.length > 0xFF) {
      throw new IllegalArgumentException("clientAddressingInformation exceeds 255 bytes");
    }
    mqttSnPacket = mqttSnPacket == null ? new byte[0] : mqttSnPacket.clone();
  }

  @Override
  public byte[] clientAddressingInformation() {
    return clientAddressingInformation.clone();
  }

  @Override
  public byte[] mqttSnPacket() {
    return mqttSnPacket.clone();
  }
}
