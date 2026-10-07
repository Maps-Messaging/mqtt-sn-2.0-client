package io.mapsmessaging.mqttsn.protection;

public record ProtectedContent(byte[] protectedPacket, byte[] authenticationTag) {
  public ProtectedContent {
    protectedPacket = protectedPacket == null ? new byte[0] : protectedPacket.clone();
    authenticationTag = authenticationTag == null ? new byte[0] : authenticationTag.clone();
  }

  @Override
  public byte[] protectedPacket() {
    return protectedPacket.clone();
  }

  @Override
  public byte[] authenticationTag() {
    return authenticationTag.clone();
  }
}
