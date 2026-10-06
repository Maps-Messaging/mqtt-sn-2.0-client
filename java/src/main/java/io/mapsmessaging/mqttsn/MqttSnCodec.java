package io.mapsmessaging.mqttsn;

import java.nio.ByteBuffer;
import java.util.Objects;

public final class MqttSnCodec {
  public static final int MAX_PACKET_SIZE = 65_535;

  private MqttSnCodec() {
  }

  /**
   * Decodes one MQTT-SN Control Packet from the buffer's current position.
   * The supplied buffer is not modified.
   *
   * MQTT-SN 2.0 CSD01, MQTT-SN-2.1.2-1.
   */
  public static DecodedPacket decode(ByteBuffer source) {
    Objects.requireNonNull(source, "source");
    ByteBuffer input = source.asReadOnlyBuffer();

    if (!input.hasRemaining()) {
      throw new MqttSnException(MqttSnError.NEED_MORE, "Length byte is incomplete");
    }

    int firstLength = Byte.toUnsignedInt(input.get());
    int packetLength;
    int headerLength;

    if (firstLength == 0x01) {
      if (input.remaining() < 3) {
        throw new MqttSnException(MqttSnError.NEED_MORE, "Extended MQTT-SN header is incomplete");
      }
      packetLength = Short.toUnsignedInt(input.getShort());
      headerLength = 4;
      if (packetLength < headerLength) {
        throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "Extended packet length is smaller than its header");
      }
    } else {
      packetLength = firstLength;
      headerLength = 2;
      if (packetLength < headerLength) {
        throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "Packet length is smaller than its header");
      }
    }

    int packetStart = source.position();
    if (source.remaining() < packetLength) {
      throw new MqttSnException(MqttSnError.NEED_MORE, "MQTT-SN packet is incomplete");
    }

    int typeOffset = packetStart + headerLength - 1;
    PacketType type = PacketType.fromValue(Byte.toUnsignedInt(source.get(typeOffset)));

    int bodyOffset = packetStart + headerLength;
    int bodyLength = packetLength - headerLength;
    ByteBuffer body = source.asReadOnlyBuffer();
    body.position(bodyOffset);
    body.limit(bodyOffset + bodyLength);
    body = body.slice().asReadOnlyBuffer();

    return new DecodedPacket(type, body, packetLength, headerLength);
  }

  /**
   * Encodes one MQTT-SN Control Packet and emits the shortest legal length
   * representation.
   */
  public static byte[] encode(PacketType type, byte[] body) {
    Objects.requireNonNull(type, "type");
    byte[] packetBody = body == null ? new byte[0] : body;

    int headerLength = packetBody.length <= 253 ? 2 : 4;
    int packetLength = packetBody.length + headerLength;
    if (packetLength > MAX_PACKET_SIZE) {
      throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "MQTT-SN packet exceeds 65535 bytes");
    }

    ByteBuffer output = ByteBuffer.allocate(packetLength);
    if (headerLength == 2) {
      output.put((byte) packetLength);
    } else {
      output.put((byte) 0x01);
      output.putShort((short) packetLength);
    }
    output.put((byte) type.value());
    output.put(packetBody);
    return output.array();
  }
}
