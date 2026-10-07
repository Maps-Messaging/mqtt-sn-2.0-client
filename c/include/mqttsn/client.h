/**
 *
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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
  uint16_t connect_packet_identifier;
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


typedef enum {
  MQTTSN_RETRY_NONE = 0,
  MQTTSN_RETRY_RETRANSMIT = 1,
  MQTTSN_RETRY_DELETE_CONNECTION = 2
} mqttsn_retry_action_t;

typedef struct {
  uint64_t retry_interval_ms;
  uint32_t maximum_retry_count;
  uint32_t retries_sent;
  uint64_t deadline_ms;
  uint8_t active;
} mqttsn_retry_timer_t;

void mqttsn_retry_timer_init(
    mqttsn_retry_timer_t *timer,
    uint64_t retry_interval_ms,
    uint32_t maximum_retry_count);

void mqttsn_retry_timer_start(
    mqttsn_retry_timer_t *timer,
    uint64_t now_ms);

void mqttsn_retry_timer_cancel(
    mqttsn_retry_timer_t *timer);

mqttsn_retry_action_t mqttsn_retry_timer_poll(
    mqttsn_retry_timer_t *timer,
    uint64_t now_ms);

typedef enum {
  MQTTSN_KEEP_ALIVE_NONE = 0,
  MQTTSN_KEEP_ALIVE_SEND_PINGREQ = 1
} mqttsn_keep_alive_action_t;

typedef struct {
  uint64_t keep_alive_ms;
  uint64_t deadline_ms;
  uint8_t active;
} mqttsn_keep_alive_timer_t;

void mqttsn_keep_alive_timer_init(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t keep_alive_ms);

void mqttsn_keep_alive_timer_start(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t now_ms);

void mqttsn_keep_alive_timer_outbound_activity(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t now_ms);

void mqttsn_keep_alive_timer_stop(
    mqttsn_keep_alive_timer_t *timer);

mqttsn_keep_alive_action_t mqttsn_keep_alive_timer_poll(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t now_ms);

void mqttsn_client_retry_exhausted(mqttsn_client_t *client);

#ifdef __cplusplus
}
#endif

#endif
