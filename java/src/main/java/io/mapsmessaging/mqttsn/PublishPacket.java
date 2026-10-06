package io.mapsmessaging.mqttsn;

public record PublishPacket(
    QoS qos,
    boolean duplicate,
    boolean retain,
    int packetIdentifier,
    TopicRef topic,
    byte[] payload) {

  public PublishPacket {
    payload = payload.clone();
  }

  @Override
  public byte[] payload() {
    return payload.clone();
  }
}
