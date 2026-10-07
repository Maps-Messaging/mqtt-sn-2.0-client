package io.mapsmessaging.mqttsn;

import java.nio.ByteBuffer;

public record DecodedPacket(
    PacketType type,
    ByteBuffer body,
    int packetLength,
    int headerLength) {

  public DecodedPacket {
    body = body.asReadOnlyBuffer();
  }

  @Override
  public ByteBuffer body() {
    return body.asReadOnlyBuffer();
  }
}
