package io.mapsmessaging.mqttsn.protection.bc;

import io.mapsmessaging.mqttsn.protection.ProtectionContext;

@FunctionalInterface
public interface ProtectionKeyResolver {
  byte[] resolveKey(ProtectionContext context);
}
