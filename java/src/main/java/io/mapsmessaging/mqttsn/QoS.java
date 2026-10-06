package io.mapsmessaging.mqttsn;

public enum QoS {
  AT_MOST_ONCE(0),
  AT_LEAST_ONCE(1),
  EXACTLY_ONCE(2);

  private final int value;

  QoS(int value) {
    this.value = value;
  }

  public int value() {
    return value;
  }

  static QoS fromValue(int value) {
    return switch (value) {
      case 0 -> AT_MOST_ONCE;
      case 1 -> AT_LEAST_ONCE;
      case 2 -> EXACTLY_ONCE;
      default -> throw new MqttSnException(
          MqttSnError.MALFORMED_PACKET, "Reserved MQTT-SN QoS");
    };
  }
}
