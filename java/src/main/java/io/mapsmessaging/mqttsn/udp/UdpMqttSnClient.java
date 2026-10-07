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

import io.mapsmessaging.mqttsn.DecodedPacket;
import io.mapsmessaging.mqttsn.MqttSnClient;
import io.mapsmessaging.mqttsn.MqttSnError;
import io.mapsmessaging.mqttsn.MqttSnException;
import io.mapsmessaging.mqttsn.MqttSnSession;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * UDP transport adapter for the transport-neutral MQTT-SN client library.
 *
 * <p>The adapter owns only datagram I/O. All MQTT-SN framing, state, and flow
 * validation remains in the core library.</p>
 */
public final class UdpMqttSnClient implements AutoCloseable {
  private final DatagramSocket socket;
  private final InetSocketAddress remoteAddress;
  private final MqttSnClient decoder;
  private final MqttSnSession session;
  private final byte[] receiveBuffer;

  public UdpMqttSnClient(InetSocketAddress remoteAddress) throws IOException {
    this(new DatagramSocket(), remoteAddress, new MqttSnSession());
  }

  public UdpMqttSnClient(
      DatagramSocket socket,
      InetSocketAddress remoteAddress,
      MqttSnSession session) {
    this.socket = Objects.requireNonNull(socket, "socket");
    this.remoteAddress = Objects.requireNonNull(remoteAddress, "remoteAddress");
    this.session = Objects.requireNonNull(session, "session");
    this.decoder = new MqttSnClient();
    this.receiveBuffer = new byte[65_535];
  }

  public MqttSnSession session() {
    return session;
  }

  public SocketAddress localAddress() {
    return socket.getLocalSocketAddress();
  }

  public InetSocketAddress remoteAddress() {
    return remoteAddress;
  }

  public void send(byte[] packet) throws IOException {
    Objects.requireNonNull(packet, "packet");
    session.trackOutbound(packet);
    socket.send(new DatagramPacket(packet, packet.length, remoteAddress));
  }

  /**
   * Receive and process one UDP datagram.
   *
   * @return number of MQTT-SN bytes consumed from the datagram
   */
  public int receive(Duration timeout, Consumer<DecodedPacket> handler) throws IOException {
    Objects.requireNonNull(timeout, "timeout");
    Objects.requireNonNull(handler, "handler");

    long millis = timeout.toMillis();
    if (millis < 0 || millis > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("timeout must fit in a positive int millisecond value");
    }
    socket.setSoTimeout((int) millis);

    DatagramPacket datagram = new DatagramPacket(receiveBuffer, receiveBuffer.length);
    socket.receive(datagram);

    if (!remoteAddress.equals(datagram.getSocketAddress())) {
      throw new IOException("Received MQTT-SN datagram from unexpected peer: "
          + datagram.getSocketAddress());
    }

    ByteBuffer data = ByteBuffer.wrap(
        datagram.getData(), datagram.getOffset(), datagram.getLength());

    int consumed = decoder.accept(data, packet -> {
      session.trackInbound(packet);
      handler.accept(packet);
    });

    if (consumed != datagram.getLength()) {
      throw new MqttSnException(
          MqttSnError.NEED_MORE,
          "UDP datagram ended with an incomplete MQTT-SN packet");
    }

    return consumed;
  }

  @Override
  public void close() {
    socket.close();
  }
}
