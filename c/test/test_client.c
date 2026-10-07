#include "mqttsn/client.h"
#include "mqttsn/mqttsn.h"
#include "mqttsn/packets.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

static void connect_client(mqttsn_client_t *client) {
  const uint8_t client_id[] = "state-test";
  mqttsn_connect_options_t options = {
      .clean_start = 1u,
      .allow_network_address_changes = 0u,
      .allow_server_suggested_values = 0u,
      .packet_identifier = 0x1001u,
      .keep_alive = 60u,
      .maximum_packet_size = 0u,
      .client_identifier = client_id,
      .client_identifier_length = sizeof(client_id) - 1u
  };
  const uint8_t connack[] = {
      0x06, MQTTSN_CONNACK, 0x00, 0x10, 0x01, 0x00
  };
  uint8_t connect[64];
  size_t written = 0u;

  mqttsn_client_init(client, 1u);
  assert(mqttsn_encode_connect(
      &options, connect, sizeof(connect), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      client, connect, written) == MQTTSN_OK);
  assert(client->state == MQTTSN_CLIENT_CONNECTING);

  assert(mqttsn_client_track_inbound(
      client, connack, sizeof(connack)) == MQTTSN_OK);
  assert(client->state == MQTTSN_CLIENT_ACTIVE);
}

static void test_connection_state(void) {
  mqttsn_client_t client;
  connect_client(&client);

  assert(mqttsn_client_can_send(&client, MQTTSN_PUBLISH));
  assert(!mqttsn_client_can_send(&client, MQTTSN_CONNACK));
}

static void test_outbound_flow_control(void) {
  const uint8_t filter[] = "sensors/+";
  mqttsn_subscribe_options_t subscribe = {
      .packet_identifier = 0x2001u,
      .topic = {
          .type = MQTTSN_TOPIC_NAME,
          .alias = 0u,
          .name = filter,
          .name_length = sizeof(filter) - 1u
      },
      .retain_handling = 0u,
      .retain_as_published = 0u,
      .maximum_qos = MQTTSN_QOS_1,
      .no_local = 0u
  };
  mqttsn_client_t client;
  uint8_t packet[64];
  size_t written = 0u;

  connect_client(&client);

  assert(mqttsn_encode_subscribe(
      &subscribe, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);

  assert(mqttsn_encode_pingreq(
      0x2002u, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_FLOW_CONTROL);
}

static void test_sleep_and_awake_state(void) {
  const mqttsn_sleepreq_options_t sleep = {
      .packet_identifier = 0x3001u,
      .retain_topic_aliases = 1u,
      .sleep_duration = 60u
  };
  const uint8_t sleepresp[] = {
      0x0A, MQTTSN_SLEEPRESP, 0x01, 0x30, 0x01,
      0x00, 0x00, 0x00, 0x3C, 0x00
  };
  const uint8_t pingresp[] = {
      0x04, MQTTSN_PINGRESP, 0x30, 0x02
  };
  mqttsn_client_t client;
  uint8_t packet[64];
  size_t written = 0u;

  connect_client(&client);

  assert(mqttsn_encode_sleepreq(
      &sleep, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);
  assert(mqttsn_client_track_inbound(
      &client, sleepresp, sizeof(sleepresp)) == MQTTSN_OK);
  assert(client.state == MQTTSN_CLIENT_ASLEEP);

  assert(!mqttsn_client_can_send(&client, MQTTSN_PUBLISH));
  assert(mqttsn_encode_pingreq(
      0x3002u, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);
  assert(client.state == MQTTSN_CLIENT_AWAKE);
  assert(!mqttsn_client_can_send(&client, MQTTSN_PUBLISH));
  assert(mqttsn_client_can_send(&client, MQTTSN_PUBACK));

  assert(mqttsn_client_track_inbound(
      &client, pingresp, sizeof(pingresp)) == MQTTSN_OK);
  assert(client.state == MQTTSN_CLIENT_ASLEEP);
}

static void test_inbound_flow_control(void) {
  const uint8_t topic[] = "a/b";
  const uint8_t payload[] = {'x'};
  mqttsn_publish_options_t publish = {
      .qos = MQTTSN_QOS_1,
      .duplicate = 0u,
      .retain = 0u,
      .packet_identifier = 0x4001u,
      .topic = {
          .type = MQTTSN_TOPIC_NAME,
          .alias = 0u,
          .name = topic,
          .name_length = sizeof(topic) - 1u
      },
      .payload = payload,
      .payload_length = sizeof(payload)
  };
  mqttsn_client_t client;
  uint8_t packet[64];
  size_t written = 0u;

  connect_client(&client);

  assert(mqttsn_encode_publish(
      &publish, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_inbound(
      &client, packet, written) == MQTTSN_OK);

  publish.packet_identifier = 0x4002u;
  assert(mqttsn_encode_publish(
      &publish, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_inbound(
      &client, packet, written) == MQTTSN_FLOW_CONTROL);

  assert(mqttsn_encode_ack(
      MQTTSN_PUBACK, 0x4001u, 0u, 0u,
      packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);
  assert(client.has_inbound_request == 0u);
}


static void test_packet_identifier_wraps_without_zero(void) {
  mqttsn_client_t client;

  mqttsn_client_init(&client, 0xFFFFu);
  assert(mqttsn_client_next_packet_identifier(&client) == 0xFFFFu);
  assert(mqttsn_client_next_packet_identifier(&client) == 1u);
  assert(mqttsn_client_next_packet_identifier(&client) == 2u);
}

static void test_retry_exhaustion_disconnects(void) {
  const uint8_t filter[] = "sensors/+";
  mqttsn_subscribe_options_t subscribe = {
      .packet_identifier = 0x5001u,
      .topic = {
          .type = MQTTSN_TOPIC_NAME,
          .alias = 0u,
          .name = filter,
          .name_length = sizeof(filter) - 1u
      },
      .retain_handling = 0u,
      .retain_as_published = 0u,
      .maximum_qos = MQTTSN_QOS_1,
      .no_local = 0u
  };
  mqttsn_client_t client;
  uint8_t packet[64];
  size_t written = 0u;

  connect_client(&client);
  assert(mqttsn_encode_subscribe(
      &subscribe, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);

  mqttsn_client_retry_exhausted(&client);

  assert(client.state == MQTTSN_CLIENT_DISCONNECTED);
  assert(client.has_outbound_request == 0u);
  assert(client.has_inbound_request == 0u);
}

static void test_same_request_can_be_tracked_as_retransmission(void) {
  const uint8_t filter[] = "sensors/+";
  mqttsn_subscribe_options_t subscribe = {
      .packet_identifier = 0x6001u,
      .topic = {
          .type = MQTTSN_TOPIC_NAME,
          .alias = 0u,
          .name = filter,
          .name_length = sizeof(filter) - 1u
      },
      .retain_handling = 0u,
      .retain_as_published = 0u,
      .maximum_qos = MQTTSN_QOS_1,
      .no_local = 0u
  };
  mqttsn_client_t client;
  uint8_t packet[64];
  size_t written = 0u;

  connect_client(&client);
  assert(mqttsn_encode_subscribe(
      &subscribe, packet, sizeof(packet), &written) == MQTTSN_OK);

  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);
  assert(client.has_outbound_request == 1u);
  assert(client.outbound_packet_identifier == 0x6001u);
}

static void test_mismatched_response_is_rejected(void) {
  const uint8_t filter[] = "sensors/+";
  mqttsn_subscribe_options_t subscribe = {
      .packet_identifier = 0x7001u,
      .topic = {
          .type = MQTTSN_TOPIC_NAME,
          .alias = 0u,
          .name = filter,
          .name_length = sizeof(filter) - 1u
      },
      .retain_handling = 0u,
      .retain_as_published = 0u,
      .maximum_qos = MQTTSN_QOS_1,
      .no_local = 0u
  };
  const uint8_t wrong_suback[] = {
      0x05, MQTTSN_SUBACK, 0x00, 0x70, 0x02
  };
  mqttsn_client_t client;
  uint8_t packet[64];
  size_t written = 0u;

  connect_client(&client);
  assert(mqttsn_encode_subscribe(
      &subscribe, packet, sizeof(packet), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, packet, written) == MQTTSN_OK);

  assert(mqttsn_client_track_inbound(
      &client, wrong_suback, sizeof(wrong_suback)) == MQTTSN_STATE_ERROR);
  assert(client.has_outbound_request == 1u);
}

static void test_state_restrictions(void) {
  mqttsn_client_t client;

  mqttsn_client_init(&client, 1u);
  assert(mqttsn_client_can_send(&client, MQTTSN_CONNECT));
  assert(mqttsn_client_can_send(&client, MQTTSN_PUBWOS));
  assert(!mqttsn_client_can_send(&client, MQTTSN_PUBLISH));
  assert(!mqttsn_client_can_send(&client, MQTTSN_SUBSCRIBE));

  client.state = MQTTSN_CLIENT_ASLEEP;
  assert(mqttsn_client_can_send(&client, MQTTSN_PINGREQ));
  assert(mqttsn_client_can_send(&client, MQTTSN_CONNECT));
  assert(mqttsn_client_can_send(&client, MQTTSN_DISCONNECT));
  assert(!mqttsn_client_can_send(&client, MQTTSN_REGISTER));

  client.state = MQTTSN_CLIENT_AWAKE;
  assert(mqttsn_client_can_send(&client, MQTTSN_PUBACK));
  assert(mqttsn_client_can_send(&client, MQTTSN_PUBREC));
  assert(mqttsn_client_can_send(&client, MQTTSN_PUBCOMP));
  assert(mqttsn_client_can_send(&client, MQTTSN_REGACK));
  assert(!mqttsn_client_can_send(&client, MQTTSN_PUBLISH));
  assert(!mqttsn_client_can_send(&client, MQTTSN_SUBSCRIBE));
}

static void test_failed_connack_disconnects(void) {
  const uint8_t client_id[] = "failed-connect";
  mqttsn_connect_options_t options = {
      .clean_start = 1u,
      .allow_network_address_changes = 0u,
      .allow_server_suggested_values = 0u,
      .packet_identifier = 0x8001u,
      .keep_alive = 60u,
      .maximum_packet_size = 0u,
      .client_identifier = client_id,
      .client_identifier_length = sizeof(client_id) - 1u
  };
  const uint8_t connack[] = {
      0x06, MQTTSN_CONNACK, 0x00, 0x80, 0x01, 0x80
  };
  mqttsn_client_t client;
  uint8_t connect[64];
  size_t written = 0u;

  mqttsn_client_init(&client, 1u);
  assert(mqttsn_encode_connect(
      &options, connect, sizeof(connect), &written) == MQTTSN_OK);
  assert(mqttsn_client_track_outbound(
      &client, connect, written) == MQTTSN_OK);
  assert(mqttsn_client_track_inbound(
      &client, connack, sizeof(connack)) == MQTTSN_OK);
  assert(client.state == MQTTSN_CLIENT_DISCONNECTED);
}

int main(void) {
  test_connection_state();
  test_outbound_flow_control();
  test_sleep_and_awake_state();
  test_inbound_flow_control();
  test_packet_identifier_wraps_without_zero();
  test_retry_exhaustion_disconnects();
  test_same_request_can_be_tracked_as_retransmission();
  test_mismatched_response_is_rejected();
  test_state_restrictions();
  test_failed_connack_disconnects();
  return 0;
}
