package io.mapsmessaging.mqttsn;

public record TopicRef(TopicType type, int alias, String name) {
  public TopicRef {
    if (type == null) {
      throw new IllegalArgumentException("type");
    }
    name = name == null ? "" : name;
    if (type == TopicType.NAME) {
      if (alias != 0) {
        throw new IllegalArgumentException("Topic Name must not carry an alias");
      }
    } else {
      if (alias < 1 || alias > 0xFFFF || !name.isEmpty()) {
        throw new IllegalArgumentException("Topic Alias must be 1..65535 and have no name");
      }
    }
  }

  public static TopicRef name(String name) {
    MqttSnTopics.validateName(name);
    return new TopicRef(TopicType.NAME, 0, name);
  }

  public static TopicRef filter(String filter) {
    MqttSnTopics.validateFilter(filter);
    return new TopicRef(TopicType.NAME, 0, filter);
  }

  public static TopicRef sessionAlias(int alias) {
    return new TopicRef(TopicType.SESSION_ALIAS, alias, "");
  }

  public static TopicRef predefinedAlias(int alias) {
    return new TopicRef(TopicType.PREDEFINED_ALIAS, alias, "");
  }
}
