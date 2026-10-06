package io.mapsmessaging.mqttsn;

final class MqttSnTopics {
  private MqttSnTopics() {
  }

  static void validateName(String value) {
    MqttSnUtf8.validate(value);
    if (value.isEmpty()) {
      throw malformed("Topic Name must not be empty");
    }
    if (value.indexOf('+') >= 0 || value.indexOf('#') >= 0) {
      throw malformed("Topic Name must not contain wildcards");
    }
    if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 0xFFFF) {
      throw malformed("Topic Name exceeds 65535 UTF-8 bytes");
    }
  }

  static void validateFilter(String value) {
    MqttSnUtf8.validate(value);
    if (value.isEmpty()) {
      throw malformed("Topic Filter must not be empty");
    }
    if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 0xFFFF) {
      throw malformed("Topic Filter exceeds 65535 UTF-8 bytes");
    }

    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '#') {
        if (i != value.length() - 1 || (i != 0 && value.charAt(i - 1) != '/')) {
          throw malformed("Multi-level wildcard must occupy the final level");
        }
      } else if (ch == '+') {
        if ((i != 0 && value.charAt(i - 1) != '/')
            || (i + 1 != value.length() && value.charAt(i + 1) != '/')) {
          throw malformed("Single-level wildcard must occupy an entire level");
        }
      }
    }
  }

  private static MqttSnException malformed(String message) {
    return new MqttSnException(MqttSnError.MALFORMED_PACKET, message);
  }
}
