# MQTT-SN 2.0 Java Client

The Java client is a transport-neutral reference implementation of MQTT-SN 2.0 intended for protocol validation.

## Maven coordinates

```xml
<dependency>
  <groupId>io.mapsmessaging</groupId>
  <artifactId>mqtt-sn-2-client</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

The artifact is built for Java 21.

## Build

From the repository root:

```bash
mvn clean verify
```

The primary JAR is written to:

```text
java/target/mqtt-sn-2-client-0.1.0-SNAPSHOT.jar
```

The build also creates source and Javadoc JARs.

## Publish a snapshot

The project uses the standard MAPS Maven repositories:

```text
Snapshots: https://repository.mapsmessaging.io/repository/maps_snapshots/
Releases:  https://repository.mapsmessaging.io/repository/maps_releases/
```

No Maven Central/Sonatype publication is used for this project.

Maven credentials are resolved using the standard MAPS server ids `maps_snapshots` and `maps_releases`. Configure the credentials you use for those repositories in `~/.m2/settings.xml`. For the current `0.1.0-SNAPSHOT` build, Maven deploys to `maps_snapshots`:

```xml
<settings>
  <servers>
    <server>
      <id>maps_snapshots</id>
      <username>YOUR_USERNAME</username>
      <password>YOUR_PASSWORD</password>
    </server>
  </servers>
</settings>
```

Then publish from the repository root:

```bash
mvn clean deploy
```

This deploys the parent POM and:

```text
io.mapsmessaging:mqtt-sn-2-client:0.1.0-SNAPSHOT
```

## Transport model

The client does not open UDP sockets, serial ports, LoRa devices, or another transport. The application supplies received bytes to the protocol/client layer and transmits the byte buffers returned by the client.

## Specification identity

The JAR contains:

```text
META-INF/mqtt-sn-spec.properties
```

This records the exact OASIS draft and source commit against which the client was built.


## Buildkite

The repository includes `.buildkite/pipeline.yaml` using the standard MAPS
`java_build_queue_aws` queue.

Branch and pull-request builds run:

```bash
mvn --batch-mode clean verify
```

and retain the Java JARs as Buildkite artifacts.

The `main` branch additionally runs:

```bash
mvn --batch-mode clean deploy -DskipTests
```

which publishes `0.1.0-SNAPSHOT` to the standard MAPS `maps_snapshots`
repository using the Maven configuration already present on the MAPS
Buildkite Java agents.


## UDP transport adapter

The Java artifact includes `io.mapsmessaging.mqttsn.udp.UdpMqttSnClient`.

UDP is deliberately an adapter over the transport-neutral protocol/session
implementation. The core library still owns no socket.

Example:

```java
var remote = new InetSocketAddress("127.0.0.1", 1884);

try (var client = new UdpMqttSnClient(remote)) {
  int packetId = client.session().nextPacketIdentifier();

  byte[] connect = MqttSnCodec.encodeConnect(
      new ConnectOptions(
          true,
          false,
          false,
          packetId,
          60,
          0,
          "mqtt-sn-test"));

  client.send(connect);

  client.receive(
      Duration.ofSeconds(5),
      packet -> System.out.println(packet.type()));
}
```

The adapter:

- validates outbound state/flow before transmitting;
- accepts one UDP datagram at a time;
- supports multiple complete MQTT-SN packets within a datagram;
- rejects an incomplete packet at a datagram boundary;
- rejects datagrams from a peer other than the configured server;
- performs no background retry, timer, or keep-alive scheduling.
