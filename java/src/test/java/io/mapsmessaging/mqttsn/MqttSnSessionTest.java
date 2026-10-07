package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class MqttSnSessionTest {

  @Test
  void connectTransitionsToActiveOnMatchingSuccessfulConnAck() {
    MqttSnSession session = new MqttSnSession();

    byte[] connect = MqttSnCodec.encodeConnect(
        new ConnectOptions(true, false, false, 0x1001, 60, 0, "state-test"));
    session.trackOutbound(connect);

    assertEquals(ClientState.CONNECTING, session.state());

    session.trackInbound(new byte[] {
        0x06, 0x02, 0x00, 0x10, 0x01, 0x00
    });

    assertEquals(ClientState.ACTIVE, session.state());
    assertFalse(session.hasOutboundRequest());
  }

  @Test
  void failedConnAckTransitionsToDisconnected() {
    MqttSnSession session = new MqttSnSession();
    session.trackOutbound(MqttSnCodec.encodeConnect(
        new ConnectOptions(true, false, false, 0x1001, 60, 0, "state-test")));

    session.trackInbound(new byte[] {
        0x06, 0x02, 0x00, 0x10, 0x01, (byte) 0x80
    });

    assertEquals(ClientState.DISCONNECTED, session.state());
  }

  @Test
  void mismatchedConnAckIsRejected() {
    MqttSnSession session = new MqttSnSession();
    session.trackOutbound(MqttSnCodec.encodeConnect(
        new ConnectOptions(true, false, false, 0x1001, 60, 0, "state-test")));

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> session.trackInbound(new byte[] {
            0x06, 0x02, 0x00, 0x10, 0x02, 0x00
        }));

    assertEquals(MqttSnError.STATE_ERROR, error.error());
    assertEquals(ClientState.CONNECTING, session.state());
  }

  @Test
  void enforcesOneOutstandingOutboundRequest() {
    MqttSnSession session = activeSession();

    byte[] subscribe = MqttSnCodec.encodeSubscribe(new SubscribeOptions(
        0x2001,
        TopicRef.filter("sensors/+"),
        0,
        false,
        QoS.AT_LEAST_ONCE,
        false));
    session.trackOutbound(subscribe);

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> session.trackOutbound(MqttSnCodec.encodePingReq(0x2002)));

    assertEquals(MqttSnError.FLOW_CONTROL, error.error());
    assertTrue(session.hasOutboundRequest());
    assertEquals(0x2001, session.outboundPacketIdentifier());
  }

  @Test
  void allowsIdenticalRequestRetransmission() {
    MqttSnSession session = activeSession();
    byte[] subscribe = MqttSnCodec.encodeSubscribe(new SubscribeOptions(
        0x2001,
        TopicRef.filter("sensors/+"),
        0,
        false,
        QoS.AT_LEAST_ONCE,
        false));

    session.trackOutbound(subscribe);
    session.trackOutbound(subscribe);

    assertTrue(session.hasOutboundRequest());
    assertEquals(0x2001, session.outboundPacketIdentifier());
  }

  @Test
  void clearsOutstandingRequestOnMatchingResponse() {
    MqttSnSession session = activeSession();
    session.trackOutbound(MqttSnCodec.encodeSubscribe(new SubscribeOptions(
        0x2001,
        TopicRef.filter("sensors/+"),
        0,
        false,
        QoS.AT_LEAST_ONCE,
        false)));

    session.trackInbound(new byte[] {
        0x05, 0x09, 0x00, 0x20, 0x01
    });

    assertFalse(session.hasOutboundRequest());
  }

  @Test
  void mismatchedResponseIsRejectedAndRequestRemainsOutstanding() {
    MqttSnSession session = activeSession();
    session.trackOutbound(MqttSnCodec.encodeSubscribe(new SubscribeOptions(
        0x2001,
        TopicRef.filter("sensors/+"),
        0,
        false,
        QoS.AT_LEAST_ONCE,
        false)));

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> session.trackInbound(new byte[] {
            0x05, 0x09, 0x00, 0x20, 0x02
        }));

    assertEquals(MqttSnError.STATE_ERROR, error.error());
    assertTrue(session.hasOutboundRequest());
  }

  @Test
  void sleepAndWakeTransitionsFollowPingFlow() {
    MqttSnSession session = activeSession();

    session.trackOutbound(MqttSnCodec.encodeSleepReq(
        new SleepRequest(0x3001, true, 60)));
    session.trackInbound(new byte[] {
        0x0A, 0x14, 0x01, 0x30, 0x01,
        0x00, 0x00, 0x00, 0x3C, 0x00
    });

    assertEquals(ClientState.ASLEEP, session.state());
    assertFalse(session.canSend(PacketType.PUBLISH));
    assertTrue(session.canSend(PacketType.PINGREQ));

    session.trackOutbound(MqttSnCodec.encodePingReq(0x3002));
    assertEquals(ClientState.AWAKE, session.state());
    assertTrue(session.canSend(PacketType.PUBACK));
    assertFalse(session.canSend(PacketType.SUBSCRIBE));

    session.trackInbound(new byte[] {
        0x04, 0x0D, 0x30, 0x02
    });
    assertEquals(ClientState.ASLEEP, session.state());
  }

  @Test
  void enforcesInboundFlowControlAndAllowsMatchingAck() {
    MqttSnSession session = activeSession();

    byte[] first = MqttSnCodec.encodePublish(new PublishOptions(
        QoS.AT_LEAST_ONCE,
        false,
        false,
        0x4001,
        TopicRef.name("a/b"),
        new byte[] {'x'}));
    session.trackInbound(first);

    assertTrue(session.hasInboundRequest());
    assertEquals(0x4001, session.inboundPacketIdentifier());

    byte[] second = MqttSnCodec.encodePublish(new PublishOptions(
        QoS.AT_LEAST_ONCE,
        false,
        false,
        0x4002,
        TopicRef.name("a/b"),
        new byte[] {'y'}));

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> session.trackInbound(second));
    assertEquals(MqttSnError.FLOW_CONTROL, error.error());

    session.trackOutbound(MqttSnCodec.encodeAck(
        PacketType.PUBACK, 0x4001, null));
    assertFalse(session.hasInboundRequest());
  }

  @Test
  void qosTwoOutboundFlowRequiresPubrelAndPubcomp() {
    MqttSnSession session = activeSession();

    byte[] publish = MqttSnCodec.encodePublish(new PublishOptions(
        QoS.EXACTLY_ONCE,
        false,
        false,
        0x5001,
        TopicRef.name("a/b"),
        new byte[0]));
    session.trackOutbound(publish);

    session.trackInbound(MqttSnCodec.encodeAck(
        PacketType.PUBREC, 0x5001, null));
    assertTrue(session.hasOutboundRequest());

    session.trackOutbound(MqttSnCodec.encodeAck(
        PacketType.PUBREL, 0x5001, null));
    session.trackInbound(MqttSnCodec.encodeAck(
        PacketType.PUBCOMP, 0x5001, null));

    assertFalse(session.hasOutboundRequest());
  }

  @Test
  void packetIdentifierWrapsWithoutReturningZero() {
    MqttSnSession session = new MqttSnSession(0xFFFF);

    assertEquals(0xFFFF, session.nextPacketIdentifier());
    assertEquals(1, session.nextPacketIdentifier());
    assertEquals(2, session.nextPacketIdentifier());
  }

  @Test
  void retryExhaustionDisconnectsAndClearsFlows() {
    MqttSnSession session = activeSession();
    session.trackOutbound(MqttSnCodec.encodePingReq(0x6001));

    session.retryExhausted();

    assertEquals(ClientState.DISCONNECTED, session.state());
    assertFalse(session.hasOutboundRequest());
    assertFalse(session.hasInboundRequest());
  }

  @Test
  void stateRestrictionsMatchCsd01ClientStates() {
    MqttSnSession session = new MqttSnSession();

    assertTrue(session.canSend(PacketType.CONNECT));
    assertTrue(session.canSend(PacketType.PUBWOS));
    assertFalse(session.canSend(PacketType.PUBLISH));

    session.trackOutbound(MqttSnCodec.encodeConnect(
        new ConnectOptions(true, false, false, 0x7001, 60, 0, "state-test")));
    assertTrue(session.canSend(PacketType.AUTH));
    assertFalse(session.canSend(PacketType.SUBSCRIBE));
  }

  @Test
  void singlePacketTrackingRejectsTrailingPacketData() {
    MqttSnSession session = new MqttSnSession();
    byte[] packet = ByteBuffer.allocate(4)
        .put(new byte[] {0x02, 0x15, 0x02, 0x15})
        .array();

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> session.trackInbound(packet));

    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  private static MqttSnSession activeSession() {
    MqttSnSession session = new MqttSnSession();
    session.trackOutbound(MqttSnCodec.encodeConnect(
        new ConnectOptions(true, false, false, 0x1001, 60, 0, "state-test")));
    session.trackInbound(new byte[] {
        0x06, 0x02, 0x00, 0x10, 0x01, 0x00
    });
    return session;
  }
}
