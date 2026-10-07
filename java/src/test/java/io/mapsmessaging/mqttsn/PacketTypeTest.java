package io.mapsmessaging.mqttsn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PacketTypeTest {

  @Test
  void allCsd01PacketValuesRoundTrip() {
    for (PacketType type : PacketType.values()) {
      assertEquals(type, PacketType.fromValue(type.value()));
    }
  }

  @Test
  void reservedPacketTypesAreRejected() {
    for (int value : new int[] {0x00, 0x19, 0x7F, 0xFB, 0xFD}) {
      MqttSnException error = assertThrows(
          MqttSnException.class, () -> PacketType.fromValue(value));
      assertEquals(MqttSnError.RESERVED_TYPE, error.error());
    }
  }

  @Test
  void inputIsTreatedAsUnsignedByte() {
    assertEquals(PacketType.PROTECTION_ENCAPSULATION, PacketType.fromValue(-1));
  }
}
