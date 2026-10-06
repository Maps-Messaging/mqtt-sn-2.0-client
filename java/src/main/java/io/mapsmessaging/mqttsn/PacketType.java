package io.mapsmessaging.mqttsn;

import java.util.HashMap;
import java.util.Map;

public enum PacketType {
  CONNECT(0x01),
  CONNACK(0x02),
  PUBLISH(0x03),
  PUBACK(0x04),
  PUBREC(0x05),
  PUBREL(0x06),
  PUBCOMP(0x07),
  SUBSCRIBE(0x08),
  SUBACK(0x09),
  UNSUBSCRIBE(0x0A),
  UNSUBACK(0x0B),
  PINGREQ(0x0C),
  PINGRESP(0x0D),
  DISCONNECT(0x0E),
  AUTH(0x0F),
  REGISTER(0x10),
  REGACK(0x11),
  PUBWOS(0x12),
  SLEEPREQ(0x13),
  SLEEPRESP(0x14),
  WAKEUP(0x15),
  ADVERTISE(0x16),
  SEARCHGW(0x17),
  GWINFO(0x18),
  FORWARDER_ENCAPSULATION(0xFC),
  CONNECTION_ENCAPSULATION(0xFE),
  PROTECTION_ENCAPSULATION(0xFF);

  private static final Map<Integer, PacketType> BY_VALUE = new HashMap<>();

  static {
    for (PacketType type : values()) {
      BY_VALUE.put(type.value, type);
    }
  }

  private final int value;

  PacketType(int value) {
    this.value = value;
  }

  public int value() {
    return value;
  }

  public static PacketType fromValue(int value) {
    PacketType type = BY_VALUE.get(value & 0xFF);
    if (type == null) {
      throw new MqttSnException(MqttSnError.RESERVED_TYPE, "Reserved MQTT-SN packet type: 0x%02X".formatted(value & 0xFF));
    }
    return type;
  }
}
