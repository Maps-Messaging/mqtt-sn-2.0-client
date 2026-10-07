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

package io.mapsmessaging.mqttsn.udp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.mapsmessaging.mqttsn.ClientState;
import io.mapsmessaging.mqttsn.ConnectOptions;
import io.mapsmessaging.mqttsn.MqttSnCodec;
import io.mapsmessaging.mqttsn.MqttSnError;
import io.mapsmessaging.mqttsn.MqttSnException;
import io.mapsmessaging.mqttsn.PacketType;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class UdpMqttSnClientTest {

  @Test
  void sendsAndReceivesConnectExchangeOverLoopbackUdp() throws Exception {
    InetAddress loopback = InetAddress.getLoopbackAddress();

    try (DatagramSocket server = new DatagramSocket(new InetSocketAddress(loopback, 0));
         DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
         UdpMqttSnClient client = new UdpMqttSnClient(
             clientSocket,
             new InetSocketAddress(loopback, server.getLocalPort()),
             new io.mapsmessaging.mqttsn.MqttSnSession())) {

      byte[] connect = MqttSnCodec.encodeConnect(
          new ConnectOptions(true, false, false, 0x1234, 60, 0, "udp-test"));
      client.send(connect);

      byte[] receive = new byte[256];
      DatagramPacket inbound = new DatagramPacket(receive, receive.length);
      server.setSoTimeout(2_000);
      server.receive(inbound);

      assertArrayEquals(
          connect,
          java.util.Arrays.copyOfRange(
              inbound.getData(),
              inbound.getOffset(),
              inbound.getOffset() + inbound.getLength()));
      assertEquals(ClientState.CONNECTING, client.session().state());

      byte[] connAck = new byte[] {
          0x06, 0x02, 0x00, 0x12, 0x34, 0x00
      };
      server.send(new DatagramPacket(
          connAck,
          connAck.length,
          inbound.getSocketAddress()));

      List<PacketType> receivedTypes = new ArrayList<>();
      int consumed = client.receive(
          Duration.ofSeconds(2),
          packet -> receivedTypes.add(packet.type()));

      assertEquals(connAck.length, consumed);
      assertEquals(List.of(PacketType.CONNACK), receivedTypes);
      assertEquals(ClientState.ACTIVE, client.session().state());
    }
  }

  @Test
  void rejectsIncompletePacketAtUdpDatagramBoundary() throws Exception {
    InetAddress loopback = InetAddress.getLoopbackAddress();

    try (DatagramSocket server = new DatagramSocket(new InetSocketAddress(loopback, 0));
         DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
         UdpMqttSnClient client = new UdpMqttSnClient(
             clientSocket,
             new InetSocketAddress(loopback, server.getLocalPort()),
             new io.mapsmessaging.mqttsn.MqttSnSession())) {

      byte[] incomplete = new byte[] {0x01, 0x00};
      server.send(new DatagramPacket(
          incomplete,
          incomplete.length,
          client.localAddress()));

      MqttSnException error = assertThrows(
          MqttSnException.class,
          () -> client.receive(Duration.ofSeconds(2), packet -> { }));

      assertEquals(MqttSnError.NEED_MORE, error.error());
    }
  }

  @Test
  void rejectsUnexpectedUdpPeer() throws Exception {
    InetAddress loopback = InetAddress.getLoopbackAddress();

    try (DatagramSocket expectedServer = new DatagramSocket(new InetSocketAddress(loopback, 0));
         DatagramSocket unexpectedServer = new DatagramSocket(new InetSocketAddress(loopback, 0));
         DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
         UdpMqttSnClient client = new UdpMqttSnClient(
             clientSocket,
             new InetSocketAddress(loopback, expectedServer.getLocalPort()),
             new io.mapsmessaging.mqttsn.MqttSnSession())) {

      byte[] packet = new byte[] {0x02, 0x15};
      unexpectedServer.send(new DatagramPacket(
          packet,
          packet.length,
          client.localAddress()));

      assertThrows(
          java.io.IOException.class,
          () -> client.receive(Duration.ofSeconds(2), ignored -> { }));
    }
  }
}
