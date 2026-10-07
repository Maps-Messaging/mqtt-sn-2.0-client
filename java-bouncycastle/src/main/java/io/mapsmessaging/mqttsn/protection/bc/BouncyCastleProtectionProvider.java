package io.mapsmessaging.mqttsn.protection.bc;

import io.mapsmessaging.mqttsn.protection.ProtectedContent;
import io.mapsmessaging.mqttsn.protection.ProtectionContext;
import io.mapsmessaging.mqttsn.protection.ProtectionProvider;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;

public final class BouncyCastleProtectionProvider implements ProtectionProvider {
  private static final Provider BC = new BouncyCastleProvider();

  private final ProtectionKeyResolver keyResolver;

  public BouncyCastleProtectionProvider(ProtectionKeyResolver keyResolver) {
    if (keyResolver == null) {
      throw new IllegalArgumentException("keyResolver");
    }
    this.keyResolver = keyResolver;
  }

  @Override
  public boolean supports(int scheme) {
    return (scheme >= 0x00 && scheme <= 0x04)
        || (scheme >= 0x40 && scheme <= 0x49);
  }

  @Override
  public boolean authenticationOnly(int scheme) {
    return scheme >= 0x00 && scheme <= 0x04;
  }

  @Override
  public int authenticationTagLength(int scheme, int tagLengthCode) {
    if (!supports(scheme) || tagLengthCode == 0x02 || tagLengthCode == 0x03) {
      return 0;
    }

    int nominal = switch (scheme) {
      case 0x00, 0x01 -> 32;
      case 0x02, 0x03, 0x04 -> 16;
      case 0x40, 0x41, 0x42 -> 8;
      case 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49 -> 16;
      default -> 0;
    };

    if (!authenticationOnly(scheme)) {
      return tagLengthCode == 0x01 ? nominal : 0;
    }

    if (tagLengthCode == 0x00 || tagLengthCode == 0x01) {
      return nominal;
    }
    if (tagLengthCode >= 0x04) {
      int truncated = tagLengthCode * 2;
      return truncated <= nominal ? truncated : 0;
    }
    return 0;
  }

  @Override
  public int protectedPacketLength(int scheme, int mqttSnPacketLength) {
    return supports(scheme) ? mqttSnPacketLength : 0;
  }

  @Override
  public ProtectedContent protect(ProtectionContext context, byte[] mqttSnPacket) {
    byte[] key = resolveKey(context);
    validateKeyLength(context.scheme(), key.length);

    try {
      if (authenticationOnly(context.scheme())) {
        byte[] fullTag = mac(context, key, mqttSnPacket);
        int tagLength = authenticationTagLength(context.scheme(), context.tagLengthCode());
        return new ProtectedContent(
            mqttSnPacket,
            Arrays.copyOf(fullTag, tagLength));
      }

      byte[] combined = aead(true, context, key, mqttSnPacket, null);
      int tagLength = authenticationTagLength(context.scheme(), context.tagLengthCode());
      int ciphertextLength = combined.length - tagLength;
      return new ProtectedContent(
          Arrays.copyOf(combined, ciphertextLength),
          Arrays.copyOfRange(combined, ciphertextLength, combined.length));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("Protection operation failed", ex);
    }
  }

  @Override
  public byte[] unprotect(
      ProtectionContext context,
      byte[] protectedPacket,
      byte[] authenticationTag) {
    byte[] key = resolveKey(context);
    validateKeyLength(context.scheme(), key.length);

    try {
      if (authenticationOnly(context.scheme())) {
        byte[] fullTag = mac(context, key, protectedPacket);
        byte[] expected = Arrays.copyOf(fullTag, authenticationTag.length);
        return MessageDigest.isEqual(expected, authenticationTag)
            ? protectedPacket.clone()
            : null;
      }

      byte[] combined = new byte[protectedPacket.length + authenticationTag.length];
      System.arraycopy(protectedPacket, 0, combined, 0, protectedPacket.length);
      System.arraycopy(
          authenticationTag, 0, combined, protectedPacket.length, authenticationTag.length);
      return aead(false, context, key, combined, authenticationTag);
    } catch (GeneralSecurityException ex) {
      return null;
    }
  }

  private byte[] mac(ProtectionContext context, byte[] key, byte[] packet)
      throws GeneralSecurityException {
    String algorithm = switch (context.scheme()) {
      case 0x00 -> "HMACSHA256";
      case 0x01 -> "HMACSHA3-256";
      case 0x02, 0x03, 0x04 -> "AESCMAC";
      default -> throw new GeneralSecurityException("Not an authentication-only scheme");
    };

    Mac mac = Mac.getInstance(algorithm, BC);
    String keyAlgorithm = context.scheme() <= 0x01 ? algorithm : "AES";
    mac.init(new SecretKeySpec(key, keyAlgorithm));
    mac.update(context.authenticatedPrefix());
    mac.update(packet);
    return mac.doFinal();
  }

  private byte[] aead(
      boolean encrypt,
      ProtectionContext context,
      byte[] key,
      byte[] input,
      byte[] authenticationTag)
      throws GeneralSecurityException {
    String transformation = switch (context.scheme()) {
      case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 -> "AES/CCM/NoPadding";
      case 0x46, 0x47, 0x48 -> "AES/GCM/NoPadding";
      case 0x49 -> "ChaCha20-Poly1305";
      default -> throw new GeneralSecurityException("Not an AEAD scheme");
    };

    int tagLength = authenticationTagLength(context.scheme(), context.tagLengthCode());
    byte[] nonce = deriveNonce(context);
    Cipher cipher = Cipher.getInstance(transformation, BC);
    String keyAlgorithm = context.scheme() == 0x49 ? "ChaCha20" : "AES";
    AEADParameterSpec params = new AEADParameterSpec(
        nonce,
        tagLength * 8,
        context.authenticatedPrefix());
    cipher.init(
        encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, keyAlgorithm),
        params);
    return cipher.doFinal(input);
  }

  private static byte[] deriveNonce(ProtectionContext context)
      throws GeneralSecurityException {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(context.authenticatedPrefix());
    int length = switch (context.scheme()) {
      case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 -> 13;
      case 0x46, 0x47, 0x48, 0x49 -> 12;
      default -> throw new GeneralSecurityException("No nonce for scheme");
    };
    return Arrays.copyOf(digest, length);
  }

  private byte[] resolveKey(ProtectionContext context) {
    byte[] key = keyResolver.resolveKey(context);
    if (key == null || key.length == 0) {
      throw new IllegalArgumentException("No key available for protection context");
    }
    return key.clone();
  }

  private static void validateKeyLength(int scheme, int length) {
    int expected = switch (scheme) {
      case 0x00, 0x01 -> -1;
      case 0x02, 0x40, 0x43, 0x46 -> 16;
      case 0x03, 0x41, 0x44, 0x47 -> 24;
      case 0x04, 0x42, 0x45, 0x48, 0x49 -> 32;
      default -> 0;
    };

    if (expected == -1) {
      if (length == 0) {
        throw new IllegalArgumentException("HMAC key must not be empty");
      }
      return;
    }
    if (length != expected) {
      throw new IllegalArgumentException(
          "Invalid key length " + length + " for protection scheme 0x%02X".formatted(scheme));
    }
  }
}
