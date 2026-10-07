package io.mapsmessaging.mqttsn.protection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.mapsmessaging.mqttsn.MqttSnCodec;
import io.mapsmessaging.mqttsn.MqttSnError;
import io.mapsmessaging.mqttsn.MqttSnException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * MQTT-SN 2.0 CSD01 §3.17 Protection Encapsulation structural tests.
 *
 * Covers field length rules, scheme delegation, MQTT-SN-3.17.2.1-1..4,
 * MQTT-SN-3.17.2.2-1..4, MQTT-SN-3.17.2.3-1..8,
 * MQTT-SN-3.17.3-1 and MQTT-SN-3.17.8-1.
 */
class ProtectionCodecTest {

  private static final ProtectionProvider COPY_PROVIDER = new ProtectionProvider() {
    @Override
    public boolean supports(int scheme) {
      return scheme == 0x3C || scheme == 0x40;
    }

    @Override
    public boolean authenticationOnly(int scheme) {
      return scheme == 0x3C;
    }

    @Override
    public int authenticationTagLength(int scheme, int tagLengthCode) {
      if (tagLengthCode == 0) {
        return 6;
      }
      if (tagLengthCode == 1) {
        return scheme == 0x40 ? 8 : 16;
      }
      if (tagLengthCode >= 4) {
        return tagLengthCode * 2;
      }
      throw new IllegalArgumentException("reserved tag length");
    }

    @Override
    public int protectedPacketLength(int scheme, int mqttSnPacketLength) {
      return mqttSnPacketLength;
    }

    @Override
    public ProtectedContent protect(
        ProtectionContext context,
        byte[] mqttSnPacket) {
      byte[] tag = new byte[authenticationTagLength(
          context.scheme(), context.tagLengthCode())];
      Arrays.fill(tag, (byte) context.authenticatedPrefix().length);
      return new ProtectedContent(mqttSnPacket, tag);
    }

    @Override
    public byte[] unprotect(
        ProtectionContext context,
        byte[] protectedPacket,
        byte[] authenticationTag) {
      byte expected = (byte) context.authenticatedPrefix().length;
      for (byte value : authenticationTag) {
        if (value != expected) {
          return null;
        }
      }
      return protectedPacket;
    }
  };

  @Test
  void roundTripsAuthenticationOnlyProviderDefinedScheme() {
    byte[] inner = MqttSnCodec.encodePingReq(0x1234);
    ProtectionEnvelope envelope = new ProtectionEnvelope(
        0x3C,
        0x04,
        bytes(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08),
        bytes(0x11, 0x12, 0x13, 0x14),
        bytes(0x21, 0x22),
        bytes(0x00, 0x01),
        inner);

    byte[] encoded = ProtectionCodec.encode(envelope, COPY_PROVIDER);
    ProtectionEnvelope decoded = ProtectionCodec.decode(encoded, COPY_PROVIDER);

    assertEquals(0x3C, decoded.scheme());
    assertEquals(0x04, decoded.tagLengthCode());
    assertArrayEquals(envelope.senderIdentifier(), decoded.senderIdentifier());
    assertArrayEquals(envelope.random(), decoded.random());
    assertArrayEquals(envelope.cryptographicMaterial(), decoded.cryptographicMaterial());
    assertArrayEquals(envelope.monotonicCounter(), decoded.monotonicCounter());
    assertArrayEquals(inner, decoded.mqttSnPacket());
  }

  @Test
  void roundTripsAeadSchemeWithNominalTagCode() {
    ProtectionEnvelope envelope = new ProtectionEnvelope(
        0x40,
        0x01,
        bytes(1, 2, 3, 4, 5, 6, 7, 8),
        bytes(9, 10, 11, 12),
        new byte[12],
        new byte[4],
        MqttSnCodec.encodePingReq(1));

    ProtectionEnvelope decoded = ProtectionCodec.decode(
        ProtectionCodec.encode(envelope, COPY_PROVIDER),
        COPY_PROVIDER);

    assertEquals(0x40, decoded.scheme());
    assertArrayEquals(envelope.mqttSnPacket(), decoded.mqttSnPacket());
  }

  @Test
  void rejectsAeadWithProviderDefinedOrTruncatedTagCode() {
    ProtectionEnvelope invalid = new ProtectionEnvelope(
        0x40,
        0x04,
        new byte[8],
        new byte[4],
        new byte[0],
        new byte[0],
        MqttSnCodec.encodePingReq(1));

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> ProtectionCodec.encode(invalid, COPY_PROVIDER));

    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void rejectsReservedCounterLengthCodeOnDecode() {
    // flags 0x13 = tag code 1, counter code 3 (reserved)
    byte[] encoded = bytes(
        0x16, 0xFF, 0x13, 0x40,
        1,2,3,4,5,6,7,8,
        9,10,11,12,
        0x04,0x0C,0x00,0x01,
        0,0,0,0,0,0,0,0);

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> ProtectionCodec.decode(encoded, COPY_PROVIDER));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void rejectsForwarderAsProtectedInnerPacket() {
    byte[] inner = MqttSnCodec.encodeForwarderEncapsulation(
        new io.mapsmessaging.mqttsn.ForwarderEncapsulation(
            new byte[] {1},
            MqttSnCodec.encodePingReq(1)));

    ProtectionEnvelope envelope = new ProtectionEnvelope(
        0x3C,
        0x04,
        new byte[8],
        new byte[4],
        new byte[0],
        new byte[0],
        inner);

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> ProtectionCodec.encode(envelope, COPY_PROVIDER));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  @Test
  void rejectsAuthenticationFailure() {
    ProtectionEnvelope envelope = new ProtectionEnvelope(
        0x3C,
        0x04,
        new byte[8],
        new byte[4],
        new byte[0],
        new byte[0],
        MqttSnCodec.encodePingReq(1));

    byte[] encoded = ProtectionCodec.encode(envelope, COPY_PROVIDER);
    encoded[encoded.length - 1] ^= 0x01;

    MqttSnException error = assertThrows(
        MqttSnException.class,
        () -> ProtectionCodec.decode(encoded, COPY_PROVIDER));
    assertEquals(MqttSnError.MALFORMED_PACKET, error.error());
  }

  private static byte[] bytes(int... values) {
    byte[] result = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      result[i] = (byte) values[i];
    }
    return result;
  }
}
