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

#include <assert.h>
#include <string.h>

typedef struct {
  uint8_t complete;
  unsigned reset_count;
} test_auth_state_t;

static mqttsn_status_t initial_response(
    void *user_data,
    uint8_t *output,
    size_t capacity,
    size_t *written) {
  (void)user_data;
  if (capacity < 1u) return MQTTSN_BUFFER_TOO_SMALL;
  output[0] = 0x01u;
  *written = 1u;
  return MQTTSN_OK;
}

static mqttsn_status_t evaluate_challenge(
    void *user_data,
    const uint8_t *challenge,
    size_t challenge_length,
    uint8_t *output,
    size_t capacity,
    size_t *written) {
  test_auth_state_t *state = (test_auth_state_t *)user_data;
  if (challenge_length == 1u && challenge[0] == 0x7Fu) {
    state->complete = 1u;
    *written = 0u;
    return MQTTSN_OK;
  }
  if (capacity < 1u) return MQTTSN_BUFFER_TOO_SMALL;
  output[0] = 0x02u;
  *written = 1u;
  return MQTTSN_OK;
}

static int is_complete(void *user_data) {
  return ((test_auth_state_t *)user_data)->complete != 0u;
}

static void reset_mechanism(void *user_data) {
  test_auth_state_t *state = (test_auth_state_t *)user_data;
  state->complete = 0u;
  state->reset_count++;
}

static mqttsn_auth_mechanism_t mechanism(test_auth_state_t *state) {
  static const uint8_t method[] = "TEST";
  mqttsn_auth_mechanism_t result = {
      .user_data = state,
      .method = method,
      .method_length = sizeof(method) - 1u,
      .initial_response = initial_response,
      .evaluate_challenge = evaluate_challenge,
      .complete = is_complete,
      .reset = reset_mechanism
  };
  return result;
}

static void test_authenticated_connect(void) {
  static const uint8_t method[] = "PLAIN";
  static const uint8_t data[] = {0x01, 0x02, 0x03};
  static const uint8_t client_id[] = "client1";
  mqttsn_connect_options_t options = {
      .clean_start = 1u,
      .packet_identifier = 0x1234u,
      .keep_alive = 60u,
      .maximum_packet_size = 0u,
      .authentication_method = method,
      .authentication_method_length = sizeof(method) - 1u,
      .authentication_data = data,
      .authentication_data_length = sizeof(data),
      .client_identifier = client_id,
      .client_identifier_length = sizeof(client_id) - 1u
  };
  const uint8_t expected[] = {
      0x1C, MQTTSN_CONNECT,
      0x05,
      0x12, 0x34,
      0x02,
      0x00, 0x3C,
      0x00, 0x00,
      0x05, 'P', 'L', 'A', 'I', 'N',
      0x00, 0x03, 0x01, 0x02, 0x03,
      'c', 'l', 'i', 'e', 'n', 't', '1'
  };
  uint8_t output[64];
  size_t written = 0u;

  assert(mqttsn_encode_connect(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(written == sizeof(expected));
  assert(memcmp(output, expected, sizeof(expected)) == 0);

  options.authentication_method = NULL;
  options.authentication_method_length = 0u;
  assert(mqttsn_encode_connect(
      &options, output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);
}

static void test_generic_exchange(void) {
  test_auth_state_t state = {0};
  mqttsn_auth_mechanism_t mech = mechanism(&state);
  mqttsn_auth_exchange_t exchange;
  uint8_t response_data[32];
  size_t response_length = 0u;
  mqttsn_auth_t client_auth;
  static const uint8_t method[] = "TEST";
  static const uint8_t challenge[] = {0x10};
  mqttsn_auth_t server_auth = {
      .packet_identifier = 0x1001u,
      .reason_code = MQTTSN_AUTH_CONTINUE,
      .authentication_method = method,
      .authentication_method_length = sizeof(method) - 1u,
      .authentication_data = challenge,
      .authentication_data_length = sizeof(challenge)
  };
  static const uint8_t final_data[] = {0x7F};
  mqttsn_connack_view_t connack = {
      .packet_identifier = 0x1002u,
      .reason_code = 0u,
      .has_authentication = 1u,
      .authentication_method = method,
      .authentication_method_length = sizeof(method) - 1u,
      .authentication_data = final_data,
      .authentication_data_length = sizeof(final_data)
  };

  assert(mqttsn_auth_exchange_init(&exchange, &mech) == MQTTSN_OK);
  assert(mqttsn_auth_exchange_initial_response(
      &exchange, response_data, sizeof(response_data), &response_length) == MQTTSN_OK);
  assert(response_length == 1u && response_data[0] == 0x01u);

  assert(mqttsn_auth_exchange_continue(
      &exchange,
      &server_auth,
      0x1002u,
      response_data,
      sizeof(response_data),
      &response_length,
      &client_auth) == MQTTSN_OK);
  assert(client_auth.reason_code == MQTTSN_AUTH_CONTINUE);
  assert(response_length == 1u && response_data[0] == 0x02u);

  assert(mqttsn_auth_exchange_accept_connack(
      &exchange, &connack, response_data, sizeof(response_data)) == MQTTSN_OK);
  assert(exchange.active == 0u);
  assert(state.complete != 0u);

  assert(mqttsn_auth_exchange_begin_reauthentication(
      &exchange,
      0x2222u,
      response_data,
      sizeof(response_data),
      &response_length,
      &client_auth) == MQTTSN_OK);
  assert(client_auth.reason_code == MQTTSN_AUTH_REAUTHENTICATE);
  assert(state.reset_count == 1u);
}

static void test_method_change_is_rejected(void) {
  test_auth_state_t state = {0};
  mqttsn_auth_mechanism_t mech = mechanism(&state);
  mqttsn_auth_exchange_t exchange;
  uint8_t response[8];
  size_t written = 0u;
  mqttsn_auth_t client_auth;
  static const uint8_t other[] = "OTHER";
  mqttsn_auth_t server_auth = {
      .packet_identifier = 1u,
      .reason_code = MQTTSN_AUTH_CONTINUE,
      .authentication_method = other,
      .authentication_method_length = sizeof(other) - 1u
  };

  assert(mqttsn_auth_exchange_init(&exchange, &mech) == MQTTSN_OK);
  assert(mqttsn_auth_exchange_initial_response(
      &exchange, response, sizeof(response), &written) == MQTTSN_OK);
  assert(mqttsn_auth_exchange_continue(
      &exchange, &server_auth, 2u,
      response, sizeof(response), &written, &client_auth) == MQTTSN_STATE_ERROR);
}

int main(void) {
  test_authenticated_connect();
  test_generic_exchange();
  test_method_change_is_rejected();
  return 0;
}
