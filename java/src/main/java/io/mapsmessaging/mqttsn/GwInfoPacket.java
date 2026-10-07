package io.mapsmessaging.mqttsn;

public record GwInfoPacket(int gatewayIdentifier, byte[] gatewayAddress) {
  public GwInfoPacket {
    if (gatewayIdentifier < 0 || gatewayIdentifier > 0xFF) {
      throw new IllegalArgumentException("gatewayIdentifier must be 0..255");
    }
    gatewayAddress = gatewayAddress == null ? new byte[0] : gatewayAddress.clone();
  }

  @Override
  public byte[] gatewayAddress() {
    return gatewayAddress.clone();
  }
}
