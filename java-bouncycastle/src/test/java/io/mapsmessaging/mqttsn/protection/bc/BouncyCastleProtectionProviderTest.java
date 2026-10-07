package io.mapsmessaging.mqttsn.protection.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.mapsmessaging.mqttsn.MqttSnCodec;
import io.mapsmessaging.mqttsn.protection.ProtectedContent;
import io.mapsmessaging.mqttsn.protection.ProtectionCodec;
import io.mapsmessaging.mqttsn.protection.ProtectionEnvelope;
import io.mapsmessaging.mqttsn.protection.ProtectionContext;
import java.util.HexFormat;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

class BouncyCastleProtectionProviderTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] PREFIX =
      HEX.parseHex("1200a1b2c3d4e5f60102030405060708");
  private static final byte[] PLAINTEXT = HEX.parseHex("040c1234");

  @ParameterizedTest
  @MethodSource("vectors")
  void matchesCrossBackendVectors(
      int scheme,
      String keyHex,
      String protectedHex,
      String tagHex) {
    byte[] key = HEX.parseHex(keyHex);
    BouncyCastleProtectionProvider provider =
        new BouncyCastleProtectionProvider(context -> key);
    ProtectionContext context = context(scheme, 0x01);

    ProtectedContent protectedContent = provider.protect(context, PLAINTEXT);

    assertArrayEquals(HEX.parseHex(protectedHex), protectedContent.protectedPacket());
    assertArrayEquals(HEX.parseHex(tagHex), protectedContent.authenticationTag());
    assertArrayEquals(
        PLAINTEXT,
        provider.unprotect(
            context,
            protectedContent.protectedPacket(),
            protectedContent.authenticationTag()));
  }

  @Test
  void truncatesAuthenticationOnlyTagFromLeft() {
    byte[] key = HEX.parseHex("0b".repeat(20));
    BouncyCastleProtectionProvider provider =
        new BouncyCastleProtectionProvider(context -> key);
    ProtectionContext fullContext = context(0x00, 0x01);
    ProtectionContext truncatedContext = context(0x00, 0x04);

    byte[] full = provider.protect(fullContext, PLAINTEXT).authenticationTag();
    byte[] truncated =
        provider.protect(truncatedContext, PLAINTEXT).authenticationTag();

    assertEquals(8, truncated.length);
    assertArrayEquals(java.util.Arrays.copyOf(full, 8), truncated);
  }

  @Test
  void rejectsTamperedAuthenticationTag() {
    byte[] key = HEX.parseHex("00".repeat(16));
    BouncyCastleProtectionProvider provider =
        new BouncyCastleProtectionProvider(context -> key);
    ProtectionContext context = context(0x46, 0x01);
    ProtectedContent protectedContent = provider.protect(context, PLAINTEXT);
    byte[] tag = protectedContent.authenticationTag();
    tag[0] ^= 0x01;

    assertNull(provider.unprotect(context, protectedContent.protectedPacket(), tag));
  }


  @ParameterizedTest
  @MethodSource("schemeKeys")
  void standardSchemesRoundTripThroughProtectionEnvelope(int scheme, String keyHex) {
    byte[] key = HEX.parseHex(keyHex);
    BouncyCastleProtectionProvider provider =
        new BouncyCastleProtectionProvider(context -> key);
    ProtectionEnvelope envelope = new ProtectionEnvelope(
        scheme,
        0x01,
        HEX.parseHex("0102030405060708"),
        HEX.parseHex("11121314"),
        new byte[0],
        new byte[0],
        MqttSnCodec.encodePingReq(0x1234));

    byte[] encoded = ProtectionCodec.encode(envelope, provider);
    ProtectionEnvelope decoded = ProtectionCodec.decode(encoded, provider);

    assertEquals(scheme, decoded.scheme());
    assertArrayEquals(envelope.mqttSnPacket(), decoded.mqttSnPacket());
  }

  private static Stream<Arguments> schemeKeys() {
    return vectors().map(arguments -> Arguments.of(
        arguments.get()[0], arguments.get()[1]));
  }

  private static ProtectionContext context(int scheme, int tagLengthCode) {
    return new ProtectionContext(
        scheme,
        tagLengthCode,
        new byte[8],
        new byte[4],
        new byte[0],
        new byte[0],
        PREFIX);
  }

  private static Stream<Arguments> vectors() {
    return Stream.of(
        Arguments.of(0x00, "0b".repeat(20), "040c1234",
            "a3ae047cd0fb77256f6cbf12252733dd73075a9622780fc95be7ee03490dc8db"),
        Arguments.of(0x01, "0b".repeat(20), "040c1234",
            "130a16c674d3af9ee2d24dda7ec65c8e3c89806cea699ef621150b493e57861e"),
        Arguments.of(0x02, "2b7e151628aed2a6abf7158809cf4f3c", "040c1234",
            "a3e0372ca6e9ca552f310f01d9f00ba5"),
        Arguments.of(0x03, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "040c1234",
            "94d95a579745229a5a2d0f54dda3f6d1"),
        Arguments.of(0x04, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "040c1234",
            "791d72eaec7fd5ce0ecd112749a05673"),
        Arguments.of(0x40, "404142434445464748494a4b4c4d4e4f", "04dfc15b",
            "0e3b59a345150593"),
        Arguments.of(0x41, "404142434445464748494a4b4c4d4e4f5051525354555657", "2bdf29ea",
            "14ea27013b24bb50"),
        Arguments.of(0x42, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "358b3d1b",
            "387c8791681e3ed9"),
        Arguments.of(0x43, "404142434445464748494a4b4c4d4e4f", "04dfc15b",
            "577798b5f0e31ea24da56dd805a68cc5"),
        Arguments.of(0x44, "404142434445464748494a4b4c4d4e4f5051525354555657", "2bdf29ea",
            "600a13e6d7df0147d80564432d4ccaaa"),
        Arguments.of(0x45, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "358b3d1b",
            "9b002a22ba6e2f6f7e6748b88d42bf5c"),
        Arguments.of(0x46, "00".repeat(16), "2743129d",
            "dffa819c4fe6d41c4912a891e4c82786"),
        Arguments.of(0x47, "00".repeat(24), "631721b8",
            "e9a8babec89fb68f883d19425498d4cc"),
        Arguments.of(0x48, "00".repeat(32), "a9fa1bbd",
            "79f9e5b15a075aa22bece93beb9722cf"),
        Arguments.of(0x49, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "c1816b5e",
            "4979d51cd6ebd3132aecb6c366360ada"));
  }
}
