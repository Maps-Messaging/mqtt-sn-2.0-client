package io.mapsmessaging.mqttsn.protection;

public interface ProtectionProvider {
  boolean supports(int scheme);

  boolean authenticationOnly(int scheme);

  int authenticationTagLength(int scheme, int tagLengthCode);

  int protectedPacketLength(int scheme, int mqttSnPacketLength);

  ProtectedContent protect(
      ProtectionContext context,
      byte[] mqttSnPacket);

  byte[] unprotect(
      ProtectionContext context,
      byte[] protectedPacket,
      byte[] authenticationTag);
}
