package io.mapsmessaging.mqttsn.protection;

public record ProtectionEnvelope(
    int scheme,
    int tagLengthCode,
    byte[] senderIdentifier,
    byte[] random,
    byte[] cryptographicMaterial,
    byte[] monotonicCounter,
    byte[] mqttSnPacket) {

  public ProtectionEnvelope {
    if (scheme < 0 || scheme > 0xFF) {
      throw new IllegalArgumentException("scheme must be 0..255");
    }
    if (tagLengthCode < 0 || tagLengthCode > 0x0F) {
      throw new IllegalArgumentException("tagLengthCode must be 0..15");
    }
    senderIdentifier = senderIdentifier == null ? new byte[0] : senderIdentifier.clone();
    random = random == null ? new byte[0] : random.clone();
    cryptographicMaterial =
        cryptographicMaterial == null ? new byte[0] : cryptographicMaterial.clone();
    monotonicCounter = monotonicCounter == null ? new byte[0] : monotonicCounter.clone();
    mqttSnPacket = mqttSnPacket == null ? new byte[0] : mqttSnPacket.clone();
  }

  @Override public byte[] senderIdentifier() { return senderIdentifier.clone(); }
  @Override public byte[] random() { return random.clone(); }
  @Override public byte[] cryptographicMaterial() { return cryptographicMaterial.clone(); }
  @Override public byte[] monotonicCounter() { return monotonicCounter.clone(); }
  @Override public byte[] mqttSnPacket() { return mqttSnPacket.clone(); }
}
