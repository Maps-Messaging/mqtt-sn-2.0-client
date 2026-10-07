package io.mapsmessaging.mqttsn;

public record PubWosPacket(boolean retain, TopicRef topic, byte[] payload) {
  public PubWosPacket {
    if (topic == null) {
      throw new IllegalArgumentException("topic is required");
    }
    if (topic.type() == TopicType.SESSION_ALIAS) {
      throw new IllegalArgumentException("PUBWOS does not allow Session Topic Alias");
    }
    if (topic.type() == TopicType.NAME) {
      MqttSnTopics.validateName(topic.name());
    }
    payload = payload == null ? new byte[0] : payload.clone();
  }

  @Override
  public byte[] payload() {
    return payload.clone();
  }
}
