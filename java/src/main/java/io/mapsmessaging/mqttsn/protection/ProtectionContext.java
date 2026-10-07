package io.mapsmessaging.mqttsn.protection;

public record ProtectionContext(
    int scheme,
    int tagLengthCode,
    byte[] senderIdentifier,
    byte[] random,
    byte[] cryptographicMaterial,
    byte[] monotonicCounter,
    byte[] authenticatedPrefix) {

  public ProtectionContext {
    senderIdentifier = senderIdentifier.clone();
    random = random.clone();
    cryptographicMaterial = cryptographicMaterial.clone();
    monotonicCounter = monotonicCounter.clone();
    authenticatedPrefix = authenticatedPrefix.clone();
  }

  @Override public byte[] senderIdentifier() { return senderIdentifier.clone(); }
  @Override public byte[] random() { return random.clone(); }
  @Override public byte[] cryptographicMaterial() { return cryptographicMaterial.clone(); }
  @Override public byte[] monotonicCounter() { return monotonicCounter.clone(); }
  @Override public byte[] authenticatedPrefix() { return authenticatedPrefix.clone(); }
}
