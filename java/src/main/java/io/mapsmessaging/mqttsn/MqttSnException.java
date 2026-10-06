package io.mapsmessaging.mqttsn;

public final class MqttSnException extends RuntimeException {
  private final MqttSnError error;

  public MqttSnException(MqttSnError error, String message) {
    super(message);
    this.error = error;
  }

  public MqttSnError error() {
    return error;
  }
}
