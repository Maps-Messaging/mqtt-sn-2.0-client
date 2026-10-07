package io.mapsmessaging.mqttsn;

public record SearchGwPacket(byte[] additionalNetworkInformation) {
  public SearchGwPacket {
    additionalNetworkInformation =
        additionalNetworkInformation == null ? new byte[0] : additionalNetworkInformation.clone();
  }

  @Override
  public byte[] additionalNetworkInformation() {
    return additionalNetworkInformation.clone();
  }
}
