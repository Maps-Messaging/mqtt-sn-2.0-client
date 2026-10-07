package io.mapsmessaging.mqttsn;

public record AdvertisePacket(int gatewayIdentifier, int durationSeconds) {
  public AdvertisePacket {
    if (gatewayIdentifier < 0 || gatewayIdentifier > 0xFF) {
      throw new IllegalArgumentException("gatewayIdentifier must be 0..255");
    }
    if (durationSeconds < 0 || durationSeconds > 0xFFFF) {
      throw new IllegalArgumentException("durationSeconds must be 0..65535");
    }
  }
}
