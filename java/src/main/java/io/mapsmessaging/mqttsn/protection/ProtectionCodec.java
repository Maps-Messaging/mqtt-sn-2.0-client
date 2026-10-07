package io.mapsmessaging.mqttsn.protection;

import io.mapsmessaging.mqttsn.DecodedPacket;
import io.mapsmessaging.mqttsn.MqttSnCodec;
import io.mapsmessaging.mqttsn.MqttSnError;
import io.mapsmessaging.mqttsn.MqttSnException;
import io.mapsmessaging.mqttsn.PacketType;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * MQTT-SN 2.0 CSD01 Protection Encapsulation codec.
 *
 * <p>This class understands only the envelope structure and normative field
 * constraints. Cryptographic processing is delegated to a ProtectionProvider.</p>
 */
public final class ProtectionCodec {
  private ProtectionCodec() {
  }

  public static byte[] encode(
      ProtectionEnvelope envelope,
      ProtectionProvider provider) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(provider, "provider");

    validateEnvelopeInputs(envelope, provider);

    byte[] inner = envelope.mqttSnPacket();
    validateProtectedInnerPacket(inner);

    int counterCode = counterLengthCode(envelope.monotonicCounter().length);
    int cryptoCode = cryptoLengthCode(envelope.cryptographicMaterial().length);
    int tagCode = envelope.tagLengthCode();

    int tagLength = provider.authenticationTagLength(envelope.scheme(), tagCode);
    int protectedLength = provider.protectedPacketLength(envelope.scheme(), inner.length);
    validateTagRules(envelope.scheme(), tagCode, tagLength, provider);

    int bodyLength = 1 + 1 + 8 + 4
        + envelope.cryptographicMaterial().length
        + envelope.monotonicCounter().length
        + protectedLength
        + tagLength;

    int headerLength = bodyLength <= 253 ? 2 : 4;
    int packetLength = bodyLength + headerLength;
    if (packetLength > MqttSnCodec.MAX_PACKET_SIZE) {
      throw malformed("Protection Encapsulation exceeds maximum packet size");
    }

    ByteBuffer prefix = ByteBuffer.allocate(
        headerLength + 1 + 1 + 8 + 4
            + envelope.cryptographicMaterial().length
            + envelope.monotonicCounter().length);

    if (headerLength == 2) {
      prefix.put((byte) packetLength);
    } else {
      prefix.put((byte) 0x01);
      prefix.putShort((short) packetLength);
    }
    prefix.put((byte) PacketType.PROTECTION_ENCAPSULATION.value());

    int flags = (tagCode << 4) | (cryptoCode << 2) | counterCode;
    prefix.put((byte) flags);
    prefix.put((byte) envelope.scheme());
    prefix.put(envelope.senderIdentifier());
    prefix.put(envelope.random());
    prefix.put(envelope.cryptographicMaterial());
    prefix.put(envelope.monotonicCounter());

    byte[] authenticatedPrefix = prefix.array();
    ProtectionContext context = new ProtectionContext(
        envelope.scheme(),
        tagCode,
        envelope.senderIdentifier(),
        envelope.random(),
        envelope.cryptographicMaterial(),
        envelope.monotonicCounter(),
        authenticatedPrefix);

    ProtectedContent protectedContent = provider.protect(context, inner);
    byte[] protectedPacket = protectedContent.protectedPacket();
    byte[] authenticationTag = protectedContent.authenticationTag();

    if (protectedPacket.length != protectedLength) {
      throw malformed("Protection provider returned unexpected protected packet length");
    }
    if (authenticationTag.length != tagLength) {
      throw malformed("Protection provider returned unexpected authentication tag length");
    }

    ByteBuffer output = ByteBuffer.allocate(packetLength);
    output.put(authenticatedPrefix);
    output.put(protectedPacket);
    output.put(authenticationTag);
    return output.array();
  }

  public static ProtectionEnvelope decode(
      byte[] encoded,
      ProtectionProvider provider) {
    Objects.requireNonNull(encoded, "encoded");
    Objects.requireNonNull(provider, "provider");

    DecodedPacket outer = MqttSnCodec.decode(ByteBuffer.wrap(encoded));
    if (outer.packetLength() != encoded.length
        || outer.type() != PacketType.PROTECTION_ENCAPSULATION) {
      throw malformed("Expected exactly one Protection Encapsulation packet");
    }

    int headerLength = outer.headerLength();
    ByteBuffer body = outer.body();
    requireRemaining(body, 14, "Protection Encapsulation fixed fields");

    int flags = Byte.toUnsignedInt(body.get());
    int counterCode = flags & 0x03;
    int cryptoCode = (flags >>> 2) & 0x03;
    int tagCode = (flags >>> 4) & 0x0F;

    if (counterCode == 0x03) {
      throw malformed("Protection monotonic counter length code 3 is reserved");
    }
    if (tagCode == 0x02 || tagCode == 0x03) {
      throw malformed("Protection authentication tag length code is reserved");
    }

    int scheme = Byte.toUnsignedInt(body.get());
    validateScheme(scheme, provider);

    byte[] senderIdentifier = new byte[8];
    body.get(senderIdentifier);

    byte[] random = new byte[4];
    body.get(random);

    int cryptoLength = cryptoLengthFromCode(cryptoCode);
    int counterLength = counterLengthFromCode(counterCode);
    requireRemaining(
        body,
        cryptoLength + counterLength,
        "Protection optional material");

    byte[] cryptoMaterial = new byte[cryptoLength];
    body.get(cryptoMaterial);

    byte[] counter = new byte[counterLength];
    body.get(counter);

    int tagLength = provider.authenticationTagLength(scheme, tagCode);
    validateTagRules(scheme, tagCode, tagLength, provider);
    if (tagLength < 0 || body.remaining() <= tagLength) {
      throw malformed("Protection payload or authentication tag is truncated");
    }

    int protectedLength = body.remaining() - tagLength;
    byte[] protectedPacket = new byte[protectedLength];
    body.get(protectedPacket);

    byte[] authenticationTag = new byte[tagLength];
    body.get(authenticationTag);

    int prefixLength = encoded.length - protectedLength - tagLength;
    byte[] authenticatedPrefix = Arrays.copyOf(encoded, prefixLength);

    ProtectionContext context = new ProtectionContext(
        scheme,
        tagCode,
        senderIdentifier,
        random,
        cryptoMaterial,
        counter,
        authenticatedPrefix);

    byte[] inner = provider.unprotect(
        context,
        protectedPacket,
        authenticationTag);

    if (inner == null) {
      throw malformed("Protection provider rejected authentication");
    }
    validateProtectedInnerPacket(inner);

    return new ProtectionEnvelope(
        scheme,
        tagCode,
        senderIdentifier,
        random,
        cryptoMaterial,
        counter,
        inner);
  }

  private static void validateEnvelopeInputs(
      ProtectionEnvelope envelope,
      ProtectionProvider provider) {
    validateScheme(envelope.scheme(), provider);

    if (envelope.senderIdentifier().length != 8) {
      throw new IllegalArgumentException("senderIdentifier must be exactly 8 bytes");
    }
    if (envelope.random().length != 4) {
      throw new IllegalArgumentException("random must be exactly 4 bytes");
    }

    counterLengthCode(envelope.monotonicCounter().length);
    cryptoLengthCode(envelope.cryptographicMaterial().length);

    int tagCode = envelope.tagLengthCode();
    if (tagCode == 0x02 || tagCode == 0x03) {
      throw malformed("Protection authentication tag length code is reserved");
    }
  }

  private static void validateScheme(int scheme, ProtectionProvider provider) {
    if (!provider.supports(scheme)) {
      throw malformed("Protection provider does not support scheme 0x%02X".formatted(scheme));
    }
    if ((scheme >= 0x05 && scheme <= 0x3B)
        || (scheme >= 0x4A && scheme <= 0xEF)) {
      throw malformed("Reserved Protection Scheme");
    }
  }

  private static void validateTagRules(
      int scheme,
      int tagCode,
      int tagLength,
      ProtectionProvider provider) {
    if (tagLength <= 0) {
      throw malformed("Protection provider returned invalid authentication tag length");
    }

    boolean authenticationOnly = provider.authenticationOnly(scheme);
    if (!authenticationOnly && tagCode != 0x01) {
      throw malformed("AEAD Protection Schemes require Authentication Tag Length code 1");
    }
    if (authenticationOnly && tagCode >= 0x04) {
      int expected = tagCode * 2;
      if (tagLength != expected) {
        throw malformed("Truncated authentication tag length does not match flag value");
      }
    }
  }

  private static void validateProtectedInnerPacket(byte[] inner) {
    if (inner == null || inner.length == 0) {
      throw malformed("Protected MQTT-SN Packet is missing");
    }
    DecodedPacket decoded = MqttSnCodec.decode(ByteBuffer.wrap(inner));
    if (decoded.packetLength() != inner.length) {
      throw malformed("Protection Encapsulation must contain exactly one MQTT-SN packet");
    }
    if (decoded.type() == PacketType.FORWARDER_ENCAPSULATION) {
      throw malformed("Forwarder Encapsulation MUST NOT be protected");
    }
  }

  private static int counterLengthCode(int length) {
    return switch (length) {
      case 0 -> 0;
      case 2 -> 1;
      case 4 -> 2;
      default -> throw new IllegalArgumentException(
          "monotonicCounter must contain 0, 2, or 4 bytes");
    };
  }

  private static int counterLengthFromCode(int code) {
    return switch (code) {
      case 0 -> 0;
      case 1 -> 2;
      case 2 -> 4;
      default -> throw malformed("Reserved monotonic counter length code");
    };
  }

  private static int cryptoLengthCode(int length) {
    return switch (length) {
      case 0 -> 0;
      case 2 -> 1;
      case 4 -> 2;
      case 12 -> 3;
      default -> throw new IllegalArgumentException(
          "cryptographicMaterial must contain 0, 2, 4, or 12 bytes");
    };
  }

  private static int cryptoLengthFromCode(int code) {
    return switch (code) {
      case 0 -> 0;
      case 1 -> 2;
      case 2 -> 4;
      case 3 -> 12;
      default -> throw malformed("Invalid cryptographic material length code");
    };
  }

  private static void requireRemaining(ByteBuffer buffer, int required, String field) {
    if (buffer.remaining() < required) {
      throw malformed(field + " is truncated");
    }
  }

  private static MqttSnException malformed(String message) {
    return new MqttSnException(MqttSnError.MALFORMED_PACKET, message);
  }
}
