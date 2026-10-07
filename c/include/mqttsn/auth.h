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

#ifndef MQTT_SN_2_AUTH_H
#define MQTT_SN_2_AUTH_H

#include "mqttsn/mqttsn.h"
#include "mqttsn/packets.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MQTTSN_AUTH_SUCCESS 0x00u
#define MQTTSN_AUTH_CONTINUE 0x18u
#define MQTTSN_AUTH_REAUTHENTICATE 0x19u

typedef struct {
  void *user_data;
  const uint8_t *method;
  size_t method_length;

  mqttsn_status_t (*initial_response)(
      void *user_data,
      uint8_t *output,
      size_t output_capacity,
      size_t *written);

  mqttsn_status_t (*evaluate_challenge)(
      void *user_data,
      const uint8_t *challenge,
      size_t challenge_length,
      uint8_t *output,
      size_t output_capacity,
      size_t *written);

  int (*complete)(void *user_data);
  void (*reset)(void *user_data);
} mqttsn_auth_mechanism_t;

typedef struct {
  const mqttsn_auth_mechanism_t *mechanism;
  uint8_t active;
} mqttsn_auth_exchange_t;

mqttsn_status_t mqttsn_auth_exchange_init(
    mqttsn_auth_exchange_t *exchange,
    const mqttsn_auth_mechanism_t *mechanism);

mqttsn_status_t mqttsn_auth_exchange_initial_response(
    mqttsn_auth_exchange_t *exchange,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_auth_exchange_continue(
    mqttsn_auth_exchange_t *exchange,
    const mqttsn_auth_t *server_auth,
    uint16_t response_packet_identifier,
    uint8_t *response_data,
    size_t response_data_capacity,
    size_t *response_data_written,
    mqttsn_auth_t *client_auth);

mqttsn_status_t mqttsn_auth_exchange_accept_connack(
    mqttsn_auth_exchange_t *exchange,
    const mqttsn_connack_view_t *connack,
    uint8_t *scratch,
    size_t scratch_capacity);

mqttsn_status_t mqttsn_auth_exchange_begin_reauthentication(
    mqttsn_auth_exchange_t *exchange,
    uint16_t packet_identifier,
    uint8_t *response_data,
    size_t response_data_capacity,
    size_t *response_data_written,
    mqttsn_auth_t *client_auth);

void mqttsn_auth_exchange_reset(mqttsn_auth_exchange_t *exchange);

#ifdef __cplusplus
}
#endif

#endif
