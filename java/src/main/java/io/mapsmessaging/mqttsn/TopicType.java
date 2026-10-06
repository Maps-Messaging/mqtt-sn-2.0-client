package io.mapsmessaging.mqttsn;

public enum TopicType {
  SESSION_ALIAS(0),
  PREDEFINED_ALIAS(1),
  NAME(3);

  private final int value;

  TopicType(int value) {
    this.value = value;
  }

  public int value() {
    return value;
  }

  static TopicType fromValue(int value) {
    return switch (value) {
      case 0 -> SESSION_ALIAS;
      case 1 -> PREDEFINED_ALIAS;
      case 3 -> NAME;
      default -> throw new MqttSnException(
          MqttSnError.MALFORMED_PACKET, "Reserved MQTT-SN topic type");
    };
  }
}
