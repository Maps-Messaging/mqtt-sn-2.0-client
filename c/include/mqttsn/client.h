#ifndef MQTT_SN_2_CLIENT_H
#define MQTT_SN_2_CLIENT_H

#include "mqttsn/mqttsn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MQTTSN_CLIENT_NONE = 0,
  MQTTSN_CLIENT_DISCONNECTED = 1,
  MQTTSN_CLIENT_CONNECTING = 2,
  MQTTSN_CLIENT_ACTIVE = 3,
  MQTTSN_CLIENT_ASLEEP = 4,
  MQTTSN_CLIENT_AWAKE = 5
} mqttsn_client_state_t;

typedef struct {
  mqttsn_client_state_t state;
  uint16_t next_packet_identifier;
  uint8_t has_outbound_request;
  mqttsn_packet_type_t outbound_request_type;
  mqttsn_packet_type_t expected_response_type;
  uint16_t outbound_packet_identifier;
  uint8_t qos2_pubrel_pending;
  uint8_t has_inbound_request;
  mqttsn_packet_type_t inbound_request_type;
  uint16_t inbound_packet_identifier;
} mqttsn_client_t;

void mqttsn_client_init(mqttsn_client_t *client, uint16_t initial_packet_identifier);

uint16_t mqttsn_client_next_packet_identifier(mqttsn_client_t *client);

int mqttsn_client_can_send(
    const mqttsn_client_t *client,
    mqttsn_packet_type_t type);

/*
 * Validate and track a complete outbound packet before the transport sends it.
 * Re-supplying the same outstanding request is treated as a retransmission.
 */
mqttsn_status_t mqttsn_client_track_outbound(
    mqttsn_client_t *client,
    const uint8_t *packet,
    size_t packet_length);

/*
 * Validate and track one inbound packet from the Server.
 * State transitions and request/response correlation are applied here.
 */
mqttsn_status_t mqttsn_client_track_inbound(
    mqttsn_client_t *client,
    const uint8_t *packet,
    size_t packet_length);

void mqttsn_client_retry_exhausted(mqttsn_client_t *client);

#ifdef __cplusplus
}
#endif

#endif
