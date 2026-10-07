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

#include "mqttsn/auth.h"

#include <string.h>

static int method_matches(
    const mqttsn_auth_mechanism_t *mechanism,
    const uint8_t *method,
    size_t method_length) {
  return mechanism != NULL &&
      mechanism->method_length == method_length &&
      (method_length == 0u ||
       memcmp(mechanism->method, method, method_length) == 0);
}

mqttsn_status_t mqttsn_auth_exchange_init(
    mqttsn_auth_exchange_t *exchange,
    const mqttsn_auth_mechanism_t *mechanism) {
  if (exchange == NULL || mechanism == NULL ||
      mechanism->method == NULL || mechanism->method_length == 0u ||
      mechanism->method_length > 0xFFu ||
      !mqttsn_utf8_is_valid(mechanism->method, mechanism->method_length) ||
      mechanism->initial_response == NULL ||
      mechanism->evaluate_challenge == NULL ||
      mechanism->complete == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  exchange->mechanism = mechanism;
  exchange->active = 0u;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_auth_exchange_initial_response(
    mqttsn_auth_exchange_t *exchange,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  mqttsn_status_t status;
  if (exchange == NULL || exchange->mechanism == NULL ||
      output == NULL || written == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  status = exchange->mechanism->initial_response(
      exchange->mechanism->user_data,
      output,
      output_capacity,
      written);
  if (status == MQTTSN_OK) {
    exchange->active = 1u;
  }
  return status;
}

mqttsn_status_t mqttsn_auth_exchange_continue(
    mqttsn_auth_exchange_t *exchange,
    const mqttsn_auth_t *server_auth,
    uint16_t response_packet_identifier,
    uint8_t *response_data,
    size_t response_data_capacity,
    size_t *response_data_written,
    mqttsn_auth_t *client_auth) {
  mqttsn_status_t status;

  if (exchange == NULL || exchange->mechanism == NULL ||
      server_auth == NULL || response_data == NULL ||
      response_data_written == NULL || client_auth == NULL ||
      response_packet_identifier == 0u) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (!exchange->active ||
      server_auth->reason_code != MQTTSN_AUTH_CONTINUE ||
      !method_matches(
          exchange->mechanism,
          server_auth->authentication_method,
          server_auth->authentication_method_length)) {
    return MQTTSN_STATE_ERROR;
  }

  status = exchange->mechanism->evaluate_challenge(
      exchange->mechanism->user_data,
      server_auth->authentication_data,
      server_auth->authentication_data_length,
      response_data,
      response_data_capacity,
      response_data_written);
  if (status != MQTTSN_OK) {
    return status;
  }

  memset(client_auth, 0, sizeof(*client_auth));
  client_auth->packet_identifier = response_packet_identifier;
  client_auth->reason_code = MQTTSN_AUTH_CONTINUE;
  client_auth->authentication_method = exchange->mechanism->method;
  client_auth->authentication_method_length = exchange->mechanism->method_length;
  client_auth->authentication_data = response_data;
  client_auth->authentication_data_length = *response_data_written;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_auth_exchange_accept_connack(
    mqttsn_auth_exchange_t *exchange,
    const mqttsn_connack_view_t *connack,
    uint8_t *scratch,
    size_t scratch_capacity) {
  size_t written = 0u;
  mqttsn_status_t status;

  if (exchange == NULL || exchange->mechanism == NULL || connack == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (!exchange->active) {
    return MQTTSN_OK;
  }

  if (connack->reason_code == MQTTSN_AUTH_SUCCESS) {
    if (!connack->has_authentication ||
        !method_matches(
            exchange->mechanism,
            connack->authentication_method,
            connack->authentication_method_length)) {
      return MQTTSN_STATE_ERROR;
    }

    if (connack->authentication_data_length != 0u) {
      if (scratch == NULL) {
        return MQTTSN_INVALID_ARGUMENT;
      }
      status = exchange->mechanism->evaluate_challenge(
          exchange->mechanism->user_data,
          connack->authentication_data,
          connack->authentication_data_length,
          scratch,
          scratch_capacity,
          &written);
      if (status != MQTTSN_OK) {
        return status;
      }
    }

    if (!exchange->mechanism->complete(exchange->mechanism->user_data)) {
      return MQTTSN_STATE_ERROR;
    }
  }

  exchange->active = 0u;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_auth_exchange_begin_reauthentication(
    mqttsn_auth_exchange_t *exchange,
    uint16_t packet_identifier,
    uint8_t *response_data,
    size_t response_data_capacity,
    size_t *response_data_written,
    mqttsn_auth_t *client_auth) {
  mqttsn_status_t status;

  if (exchange == NULL || exchange->mechanism == NULL ||
      packet_identifier == 0u || response_data == NULL ||
      response_data_written == NULL || client_auth == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (exchange->active) {
    return MQTTSN_STATE_ERROR;
  }

  if (exchange->mechanism->reset != NULL) {
    exchange->mechanism->reset(exchange->mechanism->user_data);
  }

  status = exchange->mechanism->initial_response(
      exchange->mechanism->user_data,
      response_data,
      response_data_capacity,
      response_data_written);
  if (status != MQTTSN_OK) {
    return status;
  }

  exchange->active = 1u;
  memset(client_auth, 0, sizeof(*client_auth));
  client_auth->packet_identifier = packet_identifier;
  client_auth->reason_code = MQTTSN_AUTH_REAUTHENTICATE;
  client_auth->authentication_method = exchange->mechanism->method;
  client_auth->authentication_method_length = exchange->mechanism->method_length;
  client_auth->authentication_data = response_data;
  client_auth->authentication_data_length = *response_data_written;
  return MQTTSN_OK;
}

void mqttsn_auth_exchange_reset(mqttsn_auth_exchange_t *exchange) {
  if (exchange == NULL) {
    return;
  }
  if (exchange->mechanism != NULL && exchange->mechanism->reset != NULL) {
    exchange->mechanism->reset(exchange->mechanism->user_data);
  }
  exchange->active = 0u;
}
