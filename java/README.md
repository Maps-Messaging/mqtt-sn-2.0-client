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

The project uses the existing MapsMessaging snapshot repository:

```text
https://repository.mapsmessaging.io/repository/maps_snapshots/
```

Maven credentials are resolved using server id `maps_snapshots`. Configure them in `~/.m2/settings.xml`:

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
