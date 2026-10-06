package io.mapsmessaging.mqttsn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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


  public static byte[] encodeConnect(ConnectOptions options) {
    Objects.requireNonNull(options, "options");

    byte[] clientIdentifier = options.clientIdentifier().getBytes(StandardCharsets.UTF_8);
    ByteBuffer body = ByteBuffer.allocate(8 + clientIdentifier.length);
    int flags = 0;
    if (options.cleanStart()) {
      flags |= 0x01;
    }
    if (options.allowNetworkAddressChanges()) {
      flags |= 0x20;
    }
    if (options.allowServerSuggestedValues()) {
      flags |= 0x40;
    }

    body.put((byte) flags);
    body.putShort((short) options.packetIdentifier());
    body.put((byte) 0x02);
    body.putShort((short) options.keepAliveSeconds());
    body.putShort((short) options.maximumPacketSize());
    body.put(clientIdentifier);

    return encode(PacketType.CONNECT, body.array());
  }

  public static ConnAck decodeConnAck(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.CONNACK) {
      throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "Expected CONNACK");
    }

    ByteBuffer body = packet.body().asReadOnlyBuffer();
    if (body.remaining() < 4) {
      throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "CONNACK is too short");
    }

    int flags = Byte.toUnsignedInt(body.get());
    if ((flags & 0xF0) != 0) {
      throw new MqttSnException(MqttSnError.MALFORMED_PACKET, "CONNACK reserved flags are non-zero");
    }

    boolean sessionPresent = (flags & 0x01) != 0;
    int packetIdentifier = Short.toUnsignedInt(body.getShort());
    int reasonCode = Byte.toUnsignedInt(body.get());
    if (sessionPresent && reasonCode != 0) {
      throw new MqttSnException(
          MqttSnError.MALFORMED_PACKET,
          "CONNACK Session Present must be zero on failure");
    }

    Long sessionExpiry = null;
    if ((flags & 0x02) != 0) {
      requireRemaining(body, 4, "CONNACK Session Expiry Interval");
      sessionExpiry = Integer.toUnsignedLong(body.getInt());
    }

    Integer serverKeepAlive = null;
    if ((flags & 0x04) != 0) {
      requireRemaining(body, 2, "CONNACK Server Keep Alive");
      serverKeepAlive = Short.toUnsignedInt(body.getShort());
      if (serverKeepAlive == 0) {
        throw new MqttSnException(
            MqttSnError.MALFORMED_PACKET,
            "CONNACK Server Keep Alive must be greater than zero");
      }
    }

    String authenticationMethod = null;
    byte[] authenticationData = null;
    if ((flags & 0x08) != 0) {
      requireRemaining(body, 1, "CONNACK Authentication Method Length");
      int methodLength = Byte.toUnsignedInt(body.get());
      requireRemaining(body, methodLength + 2, "CONNACK Authentication Method");
      ByteBuffer method = body.slice();
      method.limit(methodLength);
      authenticationMethod = MqttSnUtf8.decode(method);
      body.position(body.position() + methodLength);

      int dataLength = Short.toUnsignedInt(body.getShort());
      requireRemaining(body, dataLength, "CONNACK Authentication Data");
      authenticationData = new byte[dataLength];
      body.get(authenticationData);
    }

    String assignedClientIdentifier = "";
    if (body.hasRemaining()) {
      assignedClientIdentifier = MqttSnUtf8.decode(body);
      body.position(body.limit());
    }

    return new ConnAck(
        sessionPresent,
        packetIdentifier,
        reasonCode,
        sessionExpiry,
        serverKeepAlive,
        authenticationMethod,
        authenticationData,
        assignedClientIdentifier);
  }

  private static void requireRemaining(ByteBuffer buffer, int required, String field) {
    if (buffer.remaining() < required) {
      throw new MqttSnException(
          MqttSnError.MALFORMED_PACKET,
          field + " is truncated");
    }
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
