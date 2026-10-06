package io.mapsmessaging.mqttsn;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Consumer;

public final class MqttSnClient {

  /**
   * Processes every complete MQTT-SN packet in the supplied buffer.
   *
   * The method owns no transport and retains no reference to the input.
   * It returns the number of bytes consumed so a stream-oriented transport
   * can retain an incomplete trailing packet.
   */
  public int accept(ByteBuffer input, Consumer<DecodedPacket> handler) {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(handler, "handler");

    int consumed = 0;
    while (consumed < input.remaining()) {
      ByteBuffer view = input.asReadOnlyBuffer();
      view.position(input.position() + consumed);
      view = view.slice();

      final DecodedPacket packet;
      try {
        packet = MqttSnCodec.decode(view);
      } catch (MqttSnException ex) {
        if (ex.error() == MqttSnError.NEED_MORE) {
          return consumed;
        }
        throw ex;
      }

      handler.accept(packet);
      consumed += packet.packetLength();
    }
    return consumed;
  }

  public byte[] encode(PacketType type, byte[] body) {
    return MqttSnCodec.encode(type, body);
  }
}
