# MQTT-SN 2.0 Java Client

The Java client is a transport-neutral reference implementation of MQTT-SN 2.0 intended for protocol validation.

## Maven coordinates

```xml
<dependency>
  <groupId>io.mapsmessaging</groupId>
  <artifactId>mqtt-sn-2-client</artifactId>
  <version>0.1.0</version>
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
java/target/mqtt-sn-2-client-0.1.0.jar
```

The build also creates source and Javadoc JARs.

## Maven publication

Published Java releases use Maven Central. The 0.1.0 release consists of the parent POM, core client and optional Bouncy Castle protection provider, with signed JAR, sources and Javadoc artifacts for both modules.

The release pipeline `.buildkite/pipeline_release.yml` runs the full Maven build and tests on `java_build_queue_aws`, then publishes with the `release` Maven profile. Release builds must use a `release-*` branch and non-SNAPSHOT module versions. Central publishing credentials and a signing key are required.

Development snapshots continue to publish to the standard MapsMessaging Nexus repository:

```text
https://repository.mapsmessaging.io/repository/maps_snapshots/
```

On a development branch with SNAPSHOT Maven versions, run:

```bash
mvn --batch-mode clean deploy
```

The snapshot repository uses the Maven server ID `maps_snapshots`. This command is not a Maven Central release.

## Transport model

The client does not open UDP sockets, serial ports, LoRa devices, or another transport. The application supplies received bytes to the protocol/client layer and transmits the byte buffers returned by the client.

## Specification identity

The JAR contains:

```text
META-INF/mqtt-sn-spec.properties
```

This records the exact OASIS draft and source commit against which the client was built.


## Buildkite

`.buildkite/pipeline.yaml` verifies the Java reactor and publishes SNAPSHOTs to MapsMessaging Nexus from `development`, using `java_build_queue_aws`. The snapshot publish step reuses the successful verification job.

`.buildkite/pipeline_release.yml` is a separate release pipeline, also on `java_build_queue_aws`. It runs the full `mvn --batch-mode --no-transfer-progress clean deploy -Prelease` lifecycle with tests enabled, signed artifact generation and Maven Central publishing.

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


## Optional Bouncy Castle protection provider

The core Java artifact remains crypto-backend-free. To use the standard CSD01
Protection Schemes with the reference Bouncy Castle backend, add:

```xml
<dependency>
  <groupId>io.mapsmessaging</groupId>
  <artifactId>mqtt-sn-2-client-protection-bc</artifactId>
  <version>0.1.0</version>
</dependency>
```

The provider artifact depends on the core client and supplies the standard
Protection Scheme implementations. A caller provides a key resolver so key
selection can depend on the Protection Context/Sender Identifier rather than
being hard-coded into the MQTT-SN library.

The root Maven reactor builds both modules. Development snapshots go to the
MapsMessaging Nexus snapshot repository; versioned releases use Maven Central.


## Enhanced authentication

The Java core exposes a mechanism-agnostic authentication API:

```java
AuthenticationExchange auth =
    new AuthenticationExchange(myMechanism);

byte[] initial = auth.initialResponse();

byte[] connect = MqttSnCodec.encodeConnect(
    options,
    auth.method(),
    initial);
```

`AuthenticationMechanism` is deliberately not SASL-specific.

For applications such as MapsMessaging that already use SASL,
`SaslAuthenticationMechanism` adapts a standard
`javax.security.sasl.SaslClient`.

Use a `SaslClient` factory when re-authentication is required so a fresh SASL
exchange can be created.

See [../docs/AUTHENTICATION.md](../docs/AUTHENTICATION.md).
