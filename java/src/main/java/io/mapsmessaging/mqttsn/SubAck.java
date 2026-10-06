package io.mapsmessaging.mqttsn;

public record SubAck(
    TopicType topicType,
    Integer topicAlias,
    int packetIdentifier,
    Integer reasonCode) {
}
