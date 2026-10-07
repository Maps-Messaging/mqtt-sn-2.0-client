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



  public static byte[] encodeRegister(int packetIdentifier, String topicName) {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    MqttSnTopics.validateName(topicName);
    byte[] topic = topicName.getBytes(StandardCharsets.UTF_8);
    ByteBuffer body = ByteBuffer.allocate(3 + topic.length);
    body.put((byte) 0x00);
    body.putShort((short) packetIdentifier);
    body.put(topic);
    return encode(PacketType.REGISTER, body.array());
  }

  public static byte[] encodePublish(PublishOptions options) {
    Objects.requireNonNull(options, "options");
    byte[] topicName = options.topic().type() == TopicType.NAME
        ? options.topic().name().getBytes(StandardCharsets.UTF_8)
        : new byte[0];
    byte[] payload = options.payload();
    int packetIdLength = options.qos() == QoS.AT_MOST_ONCE ? 0 : 2;
    int bodyLength = 1 + packetIdLength + 2 + topicName.length + payload.length;
    ByteBuffer body = ByteBuffer.allocate(bodyLength);

    int flags = options.topic().type().value();
    if (options.retain()) {
      flags |= 0x10;
    }
    flags |= options.qos().value() << 5;
    if (options.duplicate()) {
      flags |= 0x80;
    }
    body.put((byte) flags);

    if (packetIdLength != 0) {
      body.putShort((short) options.packetIdentifier());
    }

    if (options.topic().type() == TopicType.NAME) {
      body.putShort((short) topicName.length);
      body.put(topicName);
    } else {
      body.putShort((short) options.topic().alias());
    }
    body.put(payload);
    return encode(PacketType.PUBLISH, body.array());
  }

  public static PublishPacket decodePublish(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.PUBLISH) {
      throw malformed("Expected PUBLISH");
    }

    ByteBuffer body = packet.body().asReadOnlyBuffer();
    requireRemaining(body, 3, "PUBLISH");
    int flags = Byte.toUnsignedInt(body.get());
    if ((flags & 0x0C) != 0) {
      throw malformed("PUBLISH reserved flags are non-zero");
    }

    TopicType topicType = TopicType.fromValue(flags & 0x03);
    QoS qos = QoS.fromValue((flags >>> 5) & 0x03);
    boolean duplicate = (flags & 0x80) != 0;
    boolean retain = (flags & 0x10) != 0;
    if (duplicate && qos != QoS.EXACTLY_ONCE) {
      throw malformed("DUP is only valid for QoS 2");
    }

    int packetIdentifier = 0;
    if (qos != QoS.AT_MOST_ONCE) {
      requireRemaining(body, 2, "PUBLISH Packet Identifier");
      packetIdentifier = Short.toUnsignedInt(body.getShort());
      if (packetIdentifier == 0) {
        throw malformed("PUBLISH Packet Identifier must be non-zero");
      }
    }

    requireRemaining(body, 2, "PUBLISH topic value");
    int topicValue = Short.toUnsignedInt(body.getShort());
    TopicRef topic;
    if (topicType == TopicType.NAME) {
      requireRemaining(body, topicValue, "PUBLISH Topic Name");
      ByteBuffer topicBytes = body.slice();
      topicBytes.limit(topicValue);
      String name = MqttSnUtf8.decode(topicBytes);
      MqttSnTopics.validateName(name);
      topic = TopicRef.name(name);
      body.position(body.position() + topicValue);
    } else {
      if (topicValue == 0) {
        throw malformed("Topic Alias must be non-zero");
      }
      topic = topicType == TopicType.SESSION_ALIAS
          ? TopicRef.sessionAlias(topicValue)
          : TopicRef.predefinedAlias(topicValue);
    }

    byte[] payload = new byte[body.remaining()];
    body.get(payload);
    return new PublishPacket(qos, duplicate, retain, packetIdentifier, topic, payload);
  }

  public static byte[] encodeSubscribe(SubscribeOptions options) {
    Objects.requireNonNull(options, "options");
    byte[] topic = options.topic().type() == TopicType.NAME
        ? options.topic().name().getBytes(StandardCharsets.UTF_8)
        : new byte[2];
    if (options.topic().type() != TopicType.NAME) {
      ByteBuffer.wrap(topic).putShort((short) options.topic().alias());
    }

    int flags = options.topic().type().value()
        | (options.retainHandling() << 2)
        | (options.maximumQos().value() << 5);
    if (options.retainAsPublished()) {
      flags |= 0x10;
    }
    if (options.noLocal()) {
      flags |= 0x80;
    }

    ByteBuffer body = ByteBuffer.allocate(3 + topic.length);
    body.put((byte) flags);
    body.putShort((short) options.packetIdentifier());
    body.put(topic);
    return encode(PacketType.SUBSCRIBE, body.array());
  }

  public static SubAck decodeSubAck(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.SUBACK) {
      throw malformed("Expected SUBACK");
    }

    ByteBuffer body = packet.body().asReadOnlyBuffer();
    requireRemaining(body, 3, "SUBACK");
    int flags = Byte.toUnsignedInt(body.get());
    if ((flags & 0xF8) != 0) {
      throw malformed("SUBACK reserved flags are non-zero");
    }

    TopicType topicType = TopicType.fromValue(flags & 0x03);
    if (topicType == TopicType.NAME) {
      throw malformed("SUBACK Topic Type must be a Topic Alias");
    }

    int packetIdentifier = Short.toUnsignedInt(body.getShort());
    if (packetIdentifier == 0) {
      throw malformed("SUBACK Packet Identifier must be non-zero");
    }
    Integer topicAlias = null;
    if ((flags & 0x04) != 0) {
      requireRemaining(body, 2, "SUBACK Topic Alias");
      topicAlias = Short.toUnsignedInt(body.getShort());
      if (topicAlias == 0) {
        throw malformed("SUBACK Topic Alias must be non-zero");
      }
    }

    if (body.remaining() > 1) {
      throw malformed("SUBACK has unexpected trailing bytes");
    }
    Integer reasonCode = body.hasRemaining() ? Byte.toUnsignedInt(body.get()) : null;
    return new SubAck(topicType, topicAlias, packetIdentifier, reasonCode);
  }

  public static byte[] encodeUnsubscribe(int packetIdentifier, TopicRef topic) {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    Objects.requireNonNull(topic, "topic");
    byte[] topicBytes;
    if (topic.type() == TopicType.NAME) {
      MqttSnTopics.validateFilter(topic.name());
      topicBytes = topic.name().getBytes(StandardCharsets.UTF_8);
    } else {
      topicBytes = ByteBuffer.allocate(2).putShort((short) topic.alias()).array();
    }

    ByteBuffer body = ByteBuffer.allocate(3 + topicBytes.length);
    body.put((byte) topic.type().value());
    body.putShort((short) packetIdentifier);
    body.put(topicBytes);
    return encode(PacketType.UNSUBSCRIBE, body.array());
  }

  public static byte[] encodeAck(
      PacketType type, int packetIdentifier, Integer reasonCode) {
    if (!isAckType(type)) {
      throw new IllegalArgumentException("Unsupported acknowledgement type");
    }
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    ByteBuffer body = ByteBuffer.allocate(reasonCode == null ? 2 : 3);
    body.putShort((short) packetIdentifier);
    if (reasonCode != null) {
      body.put((byte) (reasonCode & 0xFF));
    }
    return encode(type, body.array());
  }

  public static Ack decodeAck(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (!isAckType(packet.type())) {
      throw malformed("Unexpected acknowledgement type");
    }
    ByteBuffer body = packet.body().asReadOnlyBuffer();
    if (body.remaining() != 2 && body.remaining() != 3) {
      throw malformed("Acknowledgement body must contain Packet Identifier and optional Reason Code");
    }
    int packetIdentifier = Short.toUnsignedInt(body.getShort());
    if (packetIdentifier == 0) {
      throw malformed("Acknowledgement Packet Identifier must be non-zero");
    }
    Integer reasonCode = body.hasRemaining() ? Byte.toUnsignedInt(body.get()) : null;
    return new Ack(packetIdentifier, reasonCode);
  }

  public static byte[] encodePingReq(int packetIdentifier) {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    return encode(
        PacketType.PINGREQ,
        ByteBuffer.allocate(2).putShort((short) packetIdentifier).array());
  }

  public static PingResp decodePingResp(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.PINGRESP) {
      throw malformed("Expected PINGRESP");
    }
    ByteBuffer body = packet.body().asReadOnlyBuffer();
    if (body.remaining() != 2 && body.remaining() != 3) {
      throw malformed("PINGRESP has invalid length");
    }
    int packetIdentifier = Short.toUnsignedInt(body.getShort());
    if (packetIdentifier == 0) {
      throw malformed("PINGRESP Packet Identifier must be non-zero");
    }
    Integer remaining = body.hasRemaining() ? Byte.toUnsignedInt(body.get()) : null;
    return new PingResp(packetIdentifier, remaining);
  }

  public static byte[] encodeSleepReq(SleepRequest request) {
    Objects.requireNonNull(request, "request");
    ByteBuffer body = ByteBuffer.allocate(7);
    body.put((byte) (request.retainTopicAliases() ? 0x01 : 0x00));
    body.putShort((short) request.packetIdentifier());
    body.putInt((int) request.sleepDurationSeconds());
    return encode(PacketType.SLEEPREQ, body.array());
  }

  public static SleepResponse decodeSleepResp(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.SLEEPRESP) {
      throw malformed("Expected SLEEPRESP");
    }
    ByteBuffer body = packet.body().asReadOnlyBuffer();
    requireRemaining(body, 3, "SLEEPRESP");
    int flags = Byte.toUnsignedInt(body.get());
    if ((flags & 0xFE) != 0) {
      throw malformed("SLEEPRESP reserved flags are non-zero");
    }
    int packetIdentifier = Short.toUnsignedInt(body.getShort());
    if (packetIdentifier == 0) {
      throw malformed("SLEEPRESP Packet Identifier must be non-zero");
    }

    Long duration = null;
    if ((flags & 0x01) != 0) {
      requireRemaining(body, 4, "SLEEPRESP Sleep Duration");
      duration = Integer.toUnsignedLong(body.getInt());
      if (duration == 0) {
        throw malformed("SLEEPRESP Sleep Duration must be greater than zero");
      }
    }

    if (body.remaining() > 1) {
      throw malformed("SLEEPRESP has unexpected trailing bytes");
    }
    Integer reasonCode = body.hasRemaining() ? Byte.toUnsignedInt(body.get()) : null;
    return new SleepResponse(packetIdentifier, duration, reasonCode);
  }





  public static byte[] encodeConnectionEncapsulation(ConnectionEncapsulation encapsulation) {
    Objects.requireNonNull(encapsulation, "encapsulation");
    byte[] clientIdentifier =
        encapsulation.clientIdentifier().getBytes(StandardCharsets.UTF_8);
    byte[] inner = encapsulation.mqttSnPacket();
    validateSingleEncapsulatedPacket(inner, true);

    ByteBuffer body = ByteBuffer.allocate(2 + clientIdentifier.length + inner.length);
    body.putShort((short) clientIdentifier.length);
    body.put(clientIdentifier);
    body.put(inner);
    return encode(PacketType.CONNECTION_ENCAPSULATION, body.array());
  }

  public static ConnectionEncapsulation decodeConnectionEncapsulation(
      DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.CONNECTION_ENCAPSULATION) {
      throw malformed("Expected Connection Encapsulation");
    }

    ByteBuffer body = packet.body();
    requireRemaining(body, 2, "Connection Encapsulation Client Identifier Length");
    int clientIdentifierLength = Short.toUnsignedInt(body.getShort());
    requireRemaining(
        body,
        clientIdentifierLength,
        "Connection Encapsulation Client Identifier");

    ByteBuffer clientIdBytes = body.slice();
    clientIdBytes.limit(clientIdentifierLength);
    String clientIdentifier = MqttSnUtf8.decode(clientIdBytes);
    body.position(body.position() + clientIdentifierLength);

    byte[] inner = new byte[body.remaining()];
    body.get(inner);
    validateSingleEncapsulatedPacket(inner, true);

    return new ConnectionEncapsulation(clientIdentifier, inner);
  }

  public static byte[] encodeForwarderEncapsulation(ForwarderEncapsulation encapsulation) {
    Objects.requireNonNull(encapsulation, "encapsulation");
    byte[] addressing = encapsulation.clientAddressingInformation();
    byte[] inner = encapsulation.mqttSnPacket();
    validateSingleEncapsulatedPacket(inner, false);

    ByteBuffer body = ByteBuffer.allocate(1 + addressing.length + inner.length);
    body.put((byte) addressing.length);
    body.put(addressing);
    body.put(inner);
    return encode(PacketType.FORWARDER_ENCAPSULATION, body.array());
  }

  public static ForwarderEncapsulation decodeForwarderEncapsulation(
      DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.FORWARDER_ENCAPSULATION) {
      throw malformed("Expected Forwarder Encapsulation");
    }

    ByteBuffer body = packet.body();
    requireRemaining(body, 1, "Forwarder Client Addressing Information Length");
    int addressingLength = Byte.toUnsignedInt(body.get());
    requireRemaining(
        body,
        addressingLength,
        "Forwarder Client Addressing Information");

    byte[] addressing = new byte[addressingLength];
    body.get(addressing);

    byte[] inner = new byte[body.remaining()];
    body.get(inner);
    validateSingleEncapsulatedPacket(inner, false);

    return new ForwarderEncapsulation(addressing, inner);
  }

  private static void validateSingleEncapsulatedPacket(byte[] inner, boolean connection) {
    if (inner.length == 0) {
      throw malformed("Encapsulation must contain one MQTT-SN packet");
    }

    DecodedPacket decoded = decode(ByteBuffer.wrap(inner));
    if (decoded.packetLength() != inner.length) {
      throw malformed("Encapsulation must contain exactly one MQTT-SN packet");
    }

    if (connection && !isConnectionEncapsulationAllowed(decoded.type())) {
      throw malformed(
          "Connection Encapsulation is not allowed for " + decoded.type());
    }
  }

  private static boolean isConnectionEncapsulationAllowed(PacketType type) {
    return type == PacketType.PUBLISH
        || type == PacketType.SUBSCRIBE
        || type == PacketType.UNSUBSCRIBE
        || type == PacketType.REGISTER
        || type == PacketType.DISCONNECT
        || type == PacketType.SLEEPREQ
        || type == PacketType.PINGREQ;
  }

  public static byte[] encodePubWos(PubWosPacket packet) {
    Objects.requireNonNull(packet, "packet");
    byte[] topicName = packet.topic().type() == TopicType.NAME
        ? packet.topic().name().getBytes(StandardCharsets.UTF_8)
        : new byte[0];
    byte[] payload = packet.payload();

    int flags = packet.topic().type().value();
    if (packet.retain()) {
      flags |= 0x10;
    }

    ByteBuffer body = ByteBuffer.allocate(3 + topicName.length + payload.length);
    body.put((byte) flags);
    if (packet.topic().type() == TopicType.NAME) {
      body.putShort((short) topicName.length);
      body.put(topicName);
    } else {
      body.putShort((short) packet.topic().alias());
    }
    body.put(payload);
    return encode(PacketType.PUBWOS, body.array());
  }

  public static PubWosPacket decodePubWos(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.PUBWOS) {
      throw malformed("Expected PUBWOS");
    }

    ByteBuffer body = packet.body().asReadOnlyBuffer();
    requireRemaining(body, 3, "PUBWOS");
    int flags = Byte.toUnsignedInt(body.get());
    if ((flags & 0xEC) != 0) {
      throw malformed("PUBWOS reserved flags are non-zero");
    }

    TopicType topicType = TopicType.fromValue(flags & 0x03);
    if (topicType == TopicType.SESSION_ALIAS) {
      throw malformed("PUBWOS Topic Type must be Predefined Topic Alias or Topic Name");
    }

    int topicValue = Short.toUnsignedInt(body.getShort());
    TopicRef topic;
    if (topicType == TopicType.NAME) {
      requireRemaining(body, topicValue, "PUBWOS Topic Name");
      ByteBuffer topicBytes = body.slice();
      topicBytes.limit(topicValue);
      String name = MqttSnUtf8.decode(topicBytes);
      MqttSnTopics.validateName(name);
      topic = TopicRef.name(name);
      body.position(body.position() + topicValue);
    } else {
      if (topicValue == 0) {
        throw malformed("PUBWOS Predefined Topic Alias must be non-zero");
      }
      topic = TopicRef.predefinedAlias(topicValue);
    }

    byte[] payload = new byte[body.remaining()];
    body.get(payload);
    return new PubWosPacket((flags & 0x10) != 0, topic, payload);
  }

  public static byte[] encodeAdvertise(AdvertisePacket packet) {
    Objects.requireNonNull(packet, "packet");
    ByteBuffer body = ByteBuffer.allocate(3);
    body.put((byte) packet.gatewayIdentifier());
    body.putShort((short) packet.durationSeconds());
    return encode(PacketType.ADVERTISE, body.array());
  }

  public static AdvertisePacket decodeAdvertise(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.ADVERTISE || packet.body().remaining() != 3) {
      throw malformed("Invalid ADVERTISE packet");
    }
    ByteBuffer body = packet.body();
    return new AdvertisePacket(
        Byte.toUnsignedInt(body.get()),
        Short.toUnsignedInt(body.getShort()));
  }

  public static byte[] encodeSearchGw(SearchGwPacket packet) {
    Objects.requireNonNull(packet, "packet");
    return encode(PacketType.SEARCHGW, packet.additionalNetworkInformation());
  }

  public static SearchGwPacket decodeSearchGw(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.SEARCHGW) {
      throw malformed("Expected SEARCHGW");
    }
    byte[] additional = new byte[packet.body().remaining()];
    packet.body().get(additional);
    return new SearchGwPacket(additional);
  }

  public static byte[] encodeGwInfo(GwInfoPacket packet) {
    Objects.requireNonNull(packet, "packet");
    byte[] address = packet.gatewayAddress();
    ByteBuffer body = ByteBuffer.allocate(1 + address.length);
    body.put((byte) packet.gatewayIdentifier());
    body.put(address);
    return encode(PacketType.GWINFO, body.array());
  }

  public static GwInfoPacket decodeGwInfo(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.GWINFO) {
      throw malformed("Expected GWINFO");
    }
    ByteBuffer body = packet.body();
    requireRemaining(body, 1, "GWINFO Gateway Identifier");
    int gatewayIdentifier = Byte.toUnsignedInt(body.get());
    byte[] address = new byte[body.remaining()];
    body.get(address);
    return new GwInfoPacket(gatewayIdentifier, address);
  }

  public static byte[] encodeAuth(AuthPacket auth) {
    Objects.requireNonNull(auth, "auth");
    byte[] method = auth.authenticationMethod().getBytes(StandardCharsets.UTF_8);
    byte[] data = auth.authenticationData();

    ByteBuffer body = ByteBuffer.allocate(4 + method.length + data.length);
    body.putShort((short) auth.packetIdentifier());
    body.put((byte) auth.reasonCode());
    body.put((byte) method.length);
    body.put(method);
    body.put(data);

    return encode(PacketType.AUTH, body.array());
  }

  public static AuthPacket decodeAuth(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.AUTH) {
      throw malformed("Expected AUTH");
    }

    ByteBuffer body = packet.body().asReadOnlyBuffer();
    requireRemaining(body, 4, "AUTH");

    int packetIdentifier = Short.toUnsignedInt(body.getShort());
    if (packetIdentifier == 0) {
      throw malformed("AUTH Packet Identifier must be non-zero");
    }

    int reasonCode = Byte.toUnsignedInt(body.get());
    int methodLength = Byte.toUnsignedInt(body.get());
    requireRemaining(body, methodLength, "AUTH Authentication Method");

    ByteBuffer methodBuffer = body.slice();
    methodBuffer.limit(methodLength);
    String method = MqttSnUtf8.decode(methodBuffer);
    body.position(body.position() + methodLength);

    byte[] data = new byte[body.remaining()];
    body.get(data);

    return new AuthPacket(packetIdentifier, reasonCode, method, data);
  }

  public static byte[] encodeDisconnect(DisconnectOptions options) {
    Objects.requireNonNull(options, "options");

    byte[] reasonString = options.reasonString().isEmpty()
        ? new byte[0]
        : options.reasonString().getBytes(StandardCharsets.UTF_8);

    int flags = 0;
    int bodyLength = 1 + reasonString.length;
    if (options.packetIdentifier() != null) {
      flags |= 0x01;
      bodyLength += 2;
    }
    if (options.sessionExpiryInterval() != null) {
      flags |= 0x02;
      bodyLength += 4;
    }
    if (options.reasonCode() != null) {
      flags |= 0x04;
      bodyLength += 1;
    }

    ByteBuffer body = ByteBuffer.allocate(bodyLength);
    body.put((byte) flags);
    if (options.packetIdentifier() != null) {
      body.putShort((short) options.packetIdentifier().intValue());
    }
    if (options.reasonCode() != null) {
      body.put((byte) options.reasonCode().intValue());
    }
    if (options.sessionExpiryInterval() != null) {
      body.putInt((int) options.sessionExpiryInterval().longValue());
    }
    body.put(reasonString);

    return encode(PacketType.DISCONNECT, body.array());
  }

  public static DisconnectPacket decodeDisconnect(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (packet.type() != PacketType.DISCONNECT) {
      throw malformed("Expected DISCONNECT");
    }

    ByteBuffer body = packet.body().asReadOnlyBuffer();
    requireRemaining(body, 1, "DISCONNECT Flags");

    int flags = Byte.toUnsignedInt(body.get());
    if ((flags & 0xF8) != 0) {
      throw malformed("DISCONNECT reserved flags are non-zero");
    }

    Integer packetIdentifier = null;
    Integer reasonCode = null;
    Long sessionExpiryInterval = null;

    if ((flags & 0x01) != 0) {
      requireRemaining(body, 2, "DISCONNECT Packet Identifier");
      packetIdentifier = Short.toUnsignedInt(body.getShort());
      if (packetIdentifier == 0) {
        throw malformed("DISCONNECT Packet Identifier must be non-zero");
      }
    }

    if ((flags & 0x04) != 0) {
      requireRemaining(body, 1, "DISCONNECT Reason Code");
      reasonCode = Byte.toUnsignedInt(body.get());
    }

    if ((flags & 0x02) != 0) {
      requireRemaining(body, 4, "DISCONNECT Session Expiry Interval");
      sessionExpiryInterval = Integer.toUnsignedLong(body.getInt());
    }

    String reasonString = body.hasRemaining() ? MqttSnUtf8.decode(body) : "";

    return new DisconnectPacket(
        packetIdentifier,
        reasonCode,
        sessionExpiryInterval,
        reasonString);
  }

  public static byte[] encodeWakeup() {
    return encode(PacketType.WAKEUP, new byte[0]);
  }

  private static boolean isAckType(PacketType type) {
    return type == PacketType.PUBACK
        || type == PacketType.PUBREC
        || type == PacketType.PUBREL
        || type == PacketType.PUBCOMP
        || type == PacketType.UNSUBACK;
  }

  private static MqttSnException malformed(String message) {
    return new MqttSnException(MqttSnError.MALFORMED_PACKET, message);
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
    if (packetIdentifier == 0) {
      throw new MqttSnException(
          MqttSnError.MALFORMED_PACKET,
          "CONNACK Packet Identifier must be non-zero");
    }
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
