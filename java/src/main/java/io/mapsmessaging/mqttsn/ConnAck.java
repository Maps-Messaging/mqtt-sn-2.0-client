package io.mapsmessaging.mqttsn;

public record ConnAck(
    boolean sessionPresent,
    int packetIdentifier,
    int reasonCode,
    Long sessionExpiryInterval,
    Integer serverKeepAlive,
    String authenticationMethod,
    byte[] authenticationData,
    String assignedClientIdentifier) {

  public ConnAck {
    authenticationData = authenticationData == null ? null : authenticationData.clone();
  }

  @Override
  public byte[] authenticationData() {
    return authenticationData == null ? null : authenticationData.clone();
  }
}
