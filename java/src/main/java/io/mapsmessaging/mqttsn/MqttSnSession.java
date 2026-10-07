/**
 *
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.mapsmessaging.mqttsn;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Transport-neutral MQTT-SN client state and flow controller.
 *
 * <p>This class owns no socket, scheduler, or clock. The caller supplies
 * complete packet buffers and drives retry/keep-alive timing externally.</p>
 */
public final class MqttSnSession {
  private ClientState state = ClientState.NONE;
  private int nextPacketIdentifier;
  private int connectPacketIdentifier;

  private PacketType outboundRequestType;
  private PacketType expectedResponseType;
  private int outboundPacketIdentifier;
  private boolean qos2PubrelPending;

  private PacketType inboundRequestType;
  private int inboundPacketIdentifier;

  public MqttSnSession() {
    this(1);
  }

  public MqttSnSession(int initialPacketIdentifier) {
    if (initialPacketIdentifier < 0 || initialPacketIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("initialPacketIdentifier must be 0..65535");
    }
    nextPacketIdentifier = initialPacketIdentifier == 0 ? 1 : initialPacketIdentifier;
  }

  public ClientState state() {
    return state;
  }

  public boolean hasOutboundRequest() {
    return outboundRequestType != null;
  }

  public boolean hasInboundRequest() {
    return inboundRequestType != null;
  }

  public int outboundPacketIdentifier() {
    return outboundPacketIdentifier;
  }

  public int inboundPacketIdentifier() {
    return inboundPacketIdentifier;
  }

  public int nextPacketIdentifier() {
    int result = nextPacketIdentifier == 0 ? 1 : nextPacketIdentifier;
    nextPacketIdentifier = result == 0xFFFF ? 1 : result + 1;

    if (hasOutboundRequest() && nextPacketIdentifier == outboundPacketIdentifier) {
      nextPacketIdentifier = nextPacketIdentifier == 0xFFFF ? 1 : nextPacketIdentifier + 1;
    }
    return result;
  }

  public boolean canSend(PacketType type) {
    Objects.requireNonNull(type, "type");

    return switch (state) {
      case NONE, DISCONNECTED -> allowedWithoutVirtualConnection(type);
      case CONNECTING -> type == PacketType.AUTH
          || type == PacketType.DISCONNECT
          || type == PacketType.PUBWOS
          || type == PacketType.SEARCHGW
          || type == PacketType.GWINFO;
      case ASLEEP -> type == PacketType.PINGREQ
          || type == PacketType.CONNECT
          || type == PacketType.DISCONNECT;
      case AWAKE -> isClientResponseType(type)
          || type == PacketType.CONNECT
          || type == PacketType.DISCONNECT;
      case ACTIVE -> type != PacketType.CONNACK
          && type != PacketType.SUBACK
          && type != PacketType.UNSUBACK
          && type != PacketType.PINGRESP
          && type != PacketType.SLEEPRESP
          && type != PacketType.ADVERTISE
          && type != PacketType.WAKEUP;
    };
  }

  public void trackOutbound(byte[] packetBytes) {
    Objects.requireNonNull(packetBytes, "packetBytes");
    DecodedPacket packet = MqttSnCodec.decode(ByteBuffer.wrap(packetBytes));
    if (packet.packetLength() != packetBytes.length) {
      throw malformed("Outbound buffer must contain exactly one MQTT-SN packet");
    }
    trackOutbound(packet);
  }

  public void trackOutbound(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");
    if (!canSend(packet.type())) {
      throw stateError("Packet " + packet.type() + " is not valid in state " + state);
    }

    trackClientResponse(packet);

    if (packet.type() == PacketType.CONNECT) {
      connectPacketIdentifier = readU16(packet.body(), 1, "CONNECT Packet Identifier");
      requireNonZero(connectPacketIdentifier, "CONNECT Packet Identifier");
      clearFlows();
      state = ClientState.CONNECTING;
      return;
    }

    if (packet.type() == PacketType.DISCONNECT) {
      clearFlows();
      state = ClientState.DISCONNECTED;
      return;
    }

    RequestInfo request = outboundRequestInfo(packet);
    if (request == null) {
      return;
    }

    if (hasOutboundRequest()) {
      if (packet.type() == PacketType.PUBREL
          && outboundRequestType == PacketType.PUBLISH
          && qos2PubrelPending
          && request.packetIdentifier() == outboundPacketIdentifier) {
        outboundRequestType = PacketType.PUBREL;
        expectedResponseType = PacketType.PUBCOMP;
        qos2PubrelPending = false;
        return;
      }

      if (packet.type() == PacketType.AUTH
          || packet.type() != outboundRequestType
          || request.packetIdentifier() != outboundPacketIdentifier) {
        throw flowError("An MQTT-SN request is already awaiting acknowledgement");
      }

      // Same request and Packet Identifier: retransmission.
      return;
    }

    outboundRequestType = packet.type();
    expectedResponseType = request.expectedResponse();
    outboundPacketIdentifier = request.packetIdentifier();
    qos2PubrelPending = false;

    if (packet.type() == PacketType.AUTH) {
      connectPacketIdentifier = request.packetIdentifier();
    }

    if (packet.type() == PacketType.PINGREQ && state == ClientState.ASLEEP) {
      state = ClientState.AWAKE;
    }
  }

  public void trackInbound(byte[] packetBytes) {
    Objects.requireNonNull(packetBytes, "packetBytes");
    DecodedPacket packet = MqttSnCodec.decode(ByteBuffer.wrap(packetBytes));
    if (packet.packetLength() != packetBytes.length) {
      throw malformed("Inbound buffer must contain exactly one MQTT-SN packet");
    }
    trackInbound(packet);
  }

  public void trackInbound(DecodedPacket packet) {
    Objects.requireNonNull(packet, "packet");

    if (packet.type() == PacketType.CONNACK) {
      if (state != ClientState.CONNECTING) {
        throw stateError("CONNACK received outside CONNECTING state");
      }
      ConnAck connAck = MqttSnCodec.decodeConnAck(packet);
      if (connAck.packetIdentifier() != connectPacketIdentifier) {
        throw stateError("CONNACK Packet Identifier does not match CONNECT/AUTH");
      }
      clearOutbound();
      state = connAck.reasonCode() == 0 ? ClientState.ACTIVE : ClientState.DISCONNECTED;
      return;
    }

    if (packet.type() == PacketType.DISCONNECT) {
      clearFlows();
      state = ClientState.DISCONNECTED;
      return;
    }

    if (hasOutboundRequest() && packet.type() == expectedResponseType) {
      int packetIdentifier = responsePacketIdentifier(packet);
      if (packetIdentifier != outboundPacketIdentifier) {
        throw stateError("Response Packet Identifier does not match outstanding request");
      }

      if (packet.type() == PacketType.PUBREC && outboundRequestType == PacketType.PUBLISH) {
        qos2PubrelPending = true;
        return;
      }

      if (packet.type() == PacketType.SLEEPRESP) {
        SleepResponse response = MqttSnCodec.decodeSleepResp(packet);
        if (response.reasonCode() == null || response.reasonCode() < 0x80) {
          state = ClientState.ASLEEP;
        }
      } else if (packet.type() == PacketType.PINGRESP && state == ClientState.AWAKE) {
        state = ClientState.ASLEEP;
      }

      clearOutbound();
      return;
    }

    trackInboundRequest(packet);
  }

  public void retryExhausted() {
    clearFlows();
    state = ClientState.DISCONNECTED;
  }

  private RequestInfo outboundRequestInfo(DecodedPacket packet) {
    ByteBuffer body = packet.body();

    return switch (packet.type()) {
      case PUBLISH -> {
        PublishPacket publish = MqttSnCodec.decodePublish(packet);
        if (publish.qos() == QoS.AT_MOST_ONCE) {
          yield null;
        }
        yield new RequestInfo(
            publish.packetIdentifier(),
            publish.qos() == QoS.AT_LEAST_ONCE ? PacketType.PUBACK : PacketType.PUBREC);
      }
      case PUBREL -> new RequestInfo(
          readU16(body, 0, "PUBREL Packet Identifier"), PacketType.PUBCOMP);
      case REGISTER -> new RequestInfo(
          readU16(body, 1, "REGISTER Packet Identifier"), PacketType.REGACK);
      case SUBSCRIBE -> new RequestInfo(
          readU16(body, 1, "SUBSCRIBE Packet Identifier"), PacketType.SUBACK);
      case UNSUBSCRIBE -> new RequestInfo(
          readU16(body, 1, "UNSUBSCRIBE Packet Identifier"), PacketType.UNSUBACK);
      case SLEEPREQ -> new RequestInfo(
          readU16(body, 1, "SLEEPREQ Packet Identifier"), PacketType.SLEEPRESP);
      case PINGREQ -> new RequestInfo(
          readU16(body, 0, "PINGREQ Packet Identifier"), PacketType.PINGRESP);
      case AUTH -> new RequestInfo(
          readU16(body, 0, "AUTH Packet Identifier"), PacketType.AUTH);
      default -> null;
    };
  }

  private void trackClientResponse(DecodedPacket packet) {
    if (!hasInboundRequest()) {
      return;
    }

    switch (packet.type()) {
      case PUBACK -> {
        requireInboundResponse(packet, PacketType.PUBLISH, MqttSnCodec.decodeAck(packet).packetIdentifier());
        clearInbound();
      }
      case PUBREC -> {
        requireInboundResponse(packet, PacketType.PUBLISH, MqttSnCodec.decodeAck(packet).packetIdentifier());
        inboundRequestType = PacketType.PUBREL;
      }
      case PUBCOMP -> {
        requireInboundResponse(packet, PacketType.PUBREL, MqttSnCodec.decodeAck(packet).packetIdentifier());
        clearInbound();
      }
      case REGACK -> {
        int packetIdentifier = readU16(packet.body(), 1, "REGACK Packet Identifier");
        requireInboundResponse(packet, PacketType.REGISTER, packetIdentifier);
        clearInbound();
      }
      default -> {
        // Not a response to an inbound flow-controlled request.
      }
    }
  }

  private void trackInboundRequest(DecodedPacket packet) {
    int packetIdentifier;
    boolean request;

    if (packet.type() == PacketType.PUBLISH) {
      PublishPacket publish = MqttSnCodec.decodePublish(packet);
      if (publish.qos() == QoS.AT_MOST_ONCE) {
        return;
      }
      packetIdentifier = publish.packetIdentifier();
      request = true;
    } else if (packet.type() == PacketType.REGISTER) {
      packetIdentifier = readU16(packet.body(), 1, "REGISTER Packet Identifier");
      request = true;
    } else if (packet.type() == PacketType.PUBREL) {
      packetIdentifier = readU16(packet.body(), 0, "PUBREL Packet Identifier");
      if (inboundRequestType != PacketType.PUBREL
          || packetIdentifier != inboundPacketIdentifier) {
        throw stateError("Unexpected PUBREL");
      }
      return;
    } else {
      return;
    }

    requireNonZero(packetIdentifier, packet.type() + " Packet Identifier");

    if (hasInboundRequest()) {
      if (inboundRequestType == packet.type() && inboundPacketIdentifier == packetIdentifier) {
        return; // retransmission
      }
      throw flowError("Server sent a second flow-controlled request before acknowledgement");
    }

    if (request) {
      inboundRequestType = packet.type();
      inboundPacketIdentifier = packetIdentifier;
    }
  }

  private int responsePacketIdentifier(DecodedPacket packet) {
    return switch (packet.type()) {
      case PUBACK, PUBREC, PUBCOMP, UNSUBACK -> MqttSnCodec.decodeAck(packet).packetIdentifier();
      case SUBACK -> MqttSnCodec.decodeSubAck(packet).packetIdentifier();
      case PINGRESP -> MqttSnCodec.decodePingResp(packet).packetIdentifier();
      case SLEEPRESP -> MqttSnCodec.decodeSleepResp(packet).packetIdentifier();
      case REGACK -> readU16(packet.body(), 1, "REGACK Packet Identifier");
      case AUTH -> readU16(packet.body(), 0, "AUTH Packet Identifier");
      default -> throw stateError("Packet is not a response to a tracked request: " + packet.type());
    };
  }

  private void requireInboundResponse(DecodedPacket packet, PacketType requestType, int packetIdentifier) {
    requireNonZero(packetIdentifier, packet.type() + " Packet Identifier");
    if (inboundRequestType != requestType || packetIdentifier != inboundPacketIdentifier) {
      throw stateError("Response does not match inbound " + requestType + " request");
    }
  }

  private static int readU16(ByteBuffer body, int offset, String field) {
    if (offset < 0 || body.limit() - offset < 2) {
      throw malformed(field + " is truncated");
    }
    return Short.toUnsignedInt(body.getShort(offset));
  }

  private static void requireNonZero(int value, String field) {
    if (value == 0) {
      throw malformed(field + " must be non-zero");
    }
  }

  private static boolean allowedWithoutVirtualConnection(PacketType type) {
    return type == PacketType.CONNECT
        || type == PacketType.PUBWOS
        || type == PacketType.SEARCHGW
        || type == PacketType.GWINFO;
  }

  private static boolean isClientResponseType(PacketType type) {
    return type == PacketType.PUBACK
        || type == PacketType.PUBREC
        || type == PacketType.PUBCOMP
        || type == PacketType.REGACK;
  }

  private void clearFlows() {
    clearOutbound();
    clearInbound();
  }

  private void clearOutbound() {
    outboundRequestType = null;
    expectedResponseType = null;
    outboundPacketIdentifier = 0;
    qos2PubrelPending = false;
  }

  private void clearInbound() {
    inboundRequestType = null;
    inboundPacketIdentifier = 0;
  }

  private static MqttSnException malformed(String message) {
    return new MqttSnException(MqttSnError.MALFORMED_PACKET, message);
  }

  private static MqttSnException stateError(String message) {
    return new MqttSnException(MqttSnError.STATE_ERROR, message);
  }

  private static MqttSnException flowError(String message) {
    return new MqttSnException(MqttSnError.FLOW_CONTROL, message);
  }

  private record RequestInfo(int packetIdentifier, PacketType expectedResponse) {
    private RequestInfo {
      requireNonZero(packetIdentifier, "Request Packet Identifier");
    }
  }
}
