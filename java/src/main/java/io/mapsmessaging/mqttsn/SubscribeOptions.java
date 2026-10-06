package io.mapsmessaging.mqttsn;

public record SubscribeOptions(
    int packetIdentifier,
    TopicRef topic,
    int retainHandling,
    boolean retainAsPublished,
    QoS maximumQos,
    boolean noLocal) {

  public SubscribeOptions {
    if (packetIdentifier < 1 || packetIdentifier > 0xFFFF) {
      throw new IllegalArgumentException("packetIdentifier must be 1..65535");
    }
    if (topic == null || maximumQos == null) {
      throw new IllegalArgumentException("topic and maximumQos are required");
    }
    if (retainHandling < 0 || retainHandling > 2) {
      throw new IllegalArgumentException("retainHandling must be 0..2");
    }
    if (topic.type() == TopicType.NAME) {
      MqttSnTopics.validateFilter(topic.name());
    }
  }
}
