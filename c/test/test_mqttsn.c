#include "mqttsn/mqttsn.h"
#include "mqttsn/packets.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static mqttsn_status_t count_packet(void *context, const mqttsn_packet_view_t *packet) {
  size_t *count = (size_t *)context;
  assert(packet != NULL);
  (*count)++;
  return MQTTSN_OK;
}

static void test_packet_types(void) {
  assert(mqttsn_packet_type_is_defined(0x01));
  assert(mqttsn_packet_type_is_defined(0x18));
  assert(mqttsn_packet_type_is_defined(0xFC));
  assert(mqttsn_packet_type_is_defined(0xFE));
  assert(mqttsn_packet_type_is_defined(0xFF));
  assert(!mqttsn_packet_type_is_defined(0x00));
  assert(!mqttsn_packet_type_is_defined(0x19));
  assert(!mqttsn_packet_type_is_defined(0xFD));
}

static void test_short_frame(void) {
  const uint8_t input[] = {0x02, MQTTSN_PINGREQ};
  mqttsn_packet_view_t packet;
  size_t consumed = 99u;

  assert(mqttsn_decode_packet(input, sizeof(input), &packet, &consumed) == MQTTSN_OK);
  assert(consumed == 2u);
  assert(packet.type == MQTTSN_PINGREQ);
  assert(packet.body_length == 0u);
  assert(packet.header_length == 2u);
}

static void test_extended_frame(void) {
  uint8_t body[252];
  uint8_t encoded[256];
  mqttsn_packet_view_t packet;
  size_t written = 0u;
  size_t consumed = 0u;

  memset(body, 0xA5, sizeof(body));
  assert(mqttsn_encode_packet(
      MQTTSN_PUBLISH, body, sizeof(body), encoded, sizeof(encoded), &written) == MQTTSN_OK);
  assert(written == 254u);
  assert(encoded[0] == 254u);

  {
    uint8_t large_body[252 + 2];
    uint8_t large_encoded[258];
    memset(large_body, 0x5A, sizeof(large_body));
    assert(mqttsn_encode_packet(
        MQTTSN_PUBLISH, large_body, sizeof(large_body),
        large_encoded, sizeof(large_encoded), &written) == MQTTSN_OK);
    assert(written == 258u);
    assert(large_encoded[0] == 0x01u);
    assert(large_encoded[1] == 0x01u);
    assert(large_encoded[2] == 0x02u);
    assert(large_encoded[3] == MQTTSN_PUBLISH);
    assert(mqttsn_decode_packet(
        large_encoded, written, &packet, &consumed) == MQTTSN_OK);
    assert(packet.header_length == 4u);
    assert(packet.body_length == sizeof(large_body));
  }
}

static void test_incomplete_and_reserved(void) {
  const uint8_t partial[] = {0x01, 0x01};
  const uint8_t reserved[] = {0x02, 0xFD};
  mqttsn_packet_view_t packet;
  size_t consumed = 0u;

  assert(mqttsn_decode_packet(partial, sizeof(partial), &packet, &consumed) == MQTTSN_NEED_MORE);
  assert(consumed == 0u);
  assert(mqttsn_decode_packet(reserved, sizeof(reserved), &packet, &consumed) == MQTTSN_RESERVED_TYPE);
}

static void test_multiple_packets(void) {
  const uint8_t input[] = {
      0x02, MQTTSN_PINGREQ,
      0x02, MQTTSN_PINGRESP
  };
  size_t count = 0u;
  size_t consumed = 0u;

  assert(mqttsn_process_input(
      input, sizeof(input), count_packet, &count, &consumed) == MQTTSN_OK);
  assert(count == 2u);
  assert(consumed == sizeof(input));
}


static void test_utf8_validation(void) {
  const uint8_t ascii[] = {'c', 'l', 'i', 'e', 'n', 't'};
  const uint8_t bom[] = {0xEF, 0xBB, 0xBF, 'x'};
  const uint8_t nul[] = {'a', 0x00, 'b'};
  const uint8_t overlong[] = {0xC0, 0x80};
  const uint8_t surrogate[] = {0xED, 0xA0, 0x80};

  assert(mqttsn_utf8_is_valid(ascii, sizeof(ascii)));
  assert(mqttsn_utf8_is_valid(bom, sizeof(bom)));
  assert(!mqttsn_utf8_is_valid(nul, sizeof(nul)));
  assert(!mqttsn_utf8_is_valid(overlong, sizeof(overlong)));
  assert(!mqttsn_utf8_is_valid(surrogate, sizeof(surrogate)));
}

static void test_basic_connect(void) {
  const uint8_t client_id[] = "client1";
  const uint8_t expected[] = {
      0x11, MQTTSN_CONNECT,
      0x01,
      0x12, 0x34,
      0x02,
      0x00, 0x3C,
      0x00, 0x00,
      'c', 'l', 'i', 'e', 'n', 't', '1'
  };
  mqttsn_connect_options_t options = {
      .clean_start = 1u,
      .allow_network_address_changes = 0u,
      .allow_server_suggested_values = 0u,
      .packet_identifier = 0x1234u,
      .keep_alive = 60u,
      .maximum_packet_size = 0u,
      .client_identifier = client_id,
      .client_identifier_length = sizeof(client_id) - 1u
  };
  uint8_t output[64];
  size_t written = 0u;

  assert(mqttsn_encode_connect(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(written == sizeof(expected));
  assert(memcmp(output, expected, sizeof(expected)) == 0);

  options.packet_identifier = 0u;
  assert(mqttsn_encode_connect(
      &options, output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);
  options.packet_identifier = 1u;

  options.keep_alive = 0u;
  assert(mqttsn_encode_connect(
      &options, output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);
  options.keep_alive = 60u;

  options.maximum_packet_size = 9u;
  assert(mqttsn_encode_connect(
      &options, output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);
}

static void test_connack_decode(void) {
  const uint8_t bytes[] = {
      0x0C, MQTTSN_CONNACK,
      0x06,
      0x12, 0x34,
      0x00,
      0x00, 0x00, 0x00, 0x78,
      0x00, 0x3C
  };
  mqttsn_packet_view_t packet;
  mqttsn_connack_view_t connack;
  size_t consumed = 0u;

  assert(mqttsn_decode_packet(
      bytes, sizeof(bytes), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_connack(&packet, &connack) == MQTTSN_OK);
  assert(connack.session_present == 0u);
  assert(connack.packet_identifier == 0x1234u);
  assert(connack.reason_code == 0u);
  assert(connack.has_session_expiry_interval == 1u);
  assert(connack.session_expiry_interval == 120u);
  assert(connack.has_server_keep_alive == 1u);
  assert(connack.server_keep_alive == 60u);
  assert(connack.has_authentication == 0u);
  assert(connack.assigned_client_identifier_length == 0u);
}

static void test_connack_rejects_reserved_flags_and_failed_session_present(void) {
  const uint8_t reserved_bytes[] = {
      0x06, MQTTSN_CONNACK, 0x80, 0x00, 0x01, 0x00
  };
  const uint8_t failed_session_bytes[] = {
      0x06, MQTTSN_CONNACK, 0x01, 0x00, 0x01, 0x80
  };
  mqttsn_packet_view_t packet;
  mqttsn_connack_view_t connack;
  size_t consumed = 0u;

  assert(mqttsn_decode_packet(
      reserved_bytes, sizeof(reserved_bytes), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_connack(&packet, &connack) == MQTTSN_MALFORMED_PACKET);

  assert(mqttsn_decode_packet(
      failed_session_bytes, sizeof(failed_session_bytes), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_connack(&packet, &connack) == MQTTSN_MALFORMED_PACKET);
}


static void test_topic_validation(void) {
  const uint8_t topic[] = "sensors/temperature";
  const uint8_t invalid_name[] = "sensors/+";
  const uint8_t filter_multi[] = "sensors/#";
  const uint8_t filter_single[] = "sensors/+/temperature";
  const uint8_t invalid_hash[] = "sensors/#/temperature";
  const uint8_t invalid_plus[] = "sensors/temp+";

  assert(mqttsn_topic_name_is_valid(topic, sizeof(topic) - 1u));
  assert(!mqttsn_topic_name_is_valid(invalid_name, sizeof(invalid_name) - 1u));
  assert(mqttsn_topic_filter_is_valid(filter_multi, sizeof(filter_multi) - 1u));
  assert(mqttsn_topic_filter_is_valid(filter_single, sizeof(filter_single) - 1u));
  assert(!mqttsn_topic_filter_is_valid(invalid_hash, sizeof(invalid_hash) - 1u));
  assert(!mqttsn_topic_filter_is_valid(invalid_plus, sizeof(invalid_plus) - 1u));
  assert(!mqttsn_topic_filter_is_valid(NULL, 0u));
}


static void test_publish_codec(void) {
  const uint8_t topic_name[] = "a/b";
  const uint8_t payload[] = {'x'};
  const uint8_t expected[] = {
      0x09, MQTTSN_PUBLISH, 0x03, 0x00, 0x03, 'a', '/', 'b', 'x'
  };
  mqttsn_publish_options_t options = {
      .qos = MQTTSN_QOS_0,
      .duplicate = 0u,
      .retain = 0u,
      .packet_identifier = 0u,
      .topic = {
          .type = MQTTSN_TOPIC_NAME,
          .alias = 0u,
          .name = topic_name,
          .name_length = sizeof(topic_name) - 1u
      },
      .payload = payload,
      .payload_length = sizeof(payload)
  };
  uint8_t output[64];
  size_t written = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_publish_view_t publish;
  size_t consumed = 0u;

  assert(mqttsn_encode_publish(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(written == sizeof(expected));
  assert(memcmp(output, expected, sizeof(expected)) == 0);

  assert(mqttsn_decode_packet(
      output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_publish(&packet, &publish) == MQTTSN_OK);
  assert(publish.qos == MQTTSN_QOS_0);
  assert(publish.packet_identifier == 0u);
  assert(publish.topic.type == MQTTSN_TOPIC_NAME);
  assert(publish.topic.name_length == 3u);
  assert(memcmp(publish.topic.name, "a/b", 3u) == 0);
  assert(publish.payload_length == 1u);
  assert(publish.payload[0] == 'x');

  options.duplicate = 1u;
  assert(mqttsn_encode_publish(
      &options, output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);
}

static void test_subscribe_and_suback(void) {
  const uint8_t filter[] = "sensors/+";
  mqttsn_subscribe_options_t options = {
      .packet_identifier = 0x1234u,
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
  const uint8_t suback_bytes[] = {
      0x08, MQTTSN_SUBACK, 0x04, 0x12, 0x34, 0x00, 0x2A, 0x00
  };
  uint8_t output[64];
  size_t written = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_suback_view_t suback;
  size_t consumed = 0u;

  assert(mqttsn_encode_subscribe(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(output[1] == MQTTSN_SUBSCRIBE);
  assert(output[2] == 0x23u);
  assert(output[3] == 0x12u && output[4] == 0x34u);
  assert(memcmp(output + 5u, filter, sizeof(filter) - 1u) == 0);

  assert(mqttsn_decode_packet(
      suback_bytes, sizeof(suback_bytes), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_suback(&packet, &suback) == MQTTSN_OK);
  assert(suback.packet_identifier == 0x1234u);
  assert(suback.has_topic_alias == 1u);
  assert(suback.topic_alias == 42u);
  assert(suback.has_reason_code == 1u);
  assert(suback.reason_code == 0u);
}

static void test_ping_and_ack(void) {
  const uint8_t expected_ping[] = {
      0x04, MQTTSN_PINGREQ, 0x12, 0x34
  };
  const uint8_t pingresp_bytes[] = {
      0x05, MQTTSN_PINGRESP, 0x12, 0x34, 0x07
  };
  uint8_t output[16];
  size_t written = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_pingresp_view_t pingresp;
  mqttsn_ack_view_t ack;
  size_t consumed = 0u;

  assert(mqttsn_encode_pingreq(
      0x1234u, output, sizeof(output), &written) == MQTTSN_OK);
  assert(written == sizeof(expected_ping));
  assert(memcmp(output, expected_ping, sizeof(expected_ping)) == 0);

  assert(mqttsn_decode_packet(
      pingresp_bytes, sizeof(pingresp_bytes), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_pingresp(&packet, &pingresp) == MQTTSN_OK);
  assert(pingresp.packet_identifier == 0x1234u);
  assert(pingresp.has_application_messages_remaining == 1u);
  assert(pingresp.application_messages_remaining == 7u);

  assert(mqttsn_encode_ack(
      MQTTSN_PUBACK, 0x1234u, 1u, 0u,
      output, sizeof(output), &written) == MQTTSN_OK);
  assert(mqttsn_decode_packet(
      output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_ack(&packet, &ack) == MQTTSN_OK);
  assert(ack.packet_identifier == 0x1234u);
  assert(ack.has_reason_code == 1u);
  assert(ack.reason_code == 0u);
}

static void test_sleep_codec(void) {
  const mqttsn_sleepreq_options_t options = {
      .packet_identifier = 0x1234u,
      .retain_topic_aliases = 1u,
      .sleep_duration = 60u
  };
  const uint8_t expected[] = {
      0x09, MQTTSN_SLEEPREQ, 0x01, 0x12, 0x34,
      0x00, 0x00, 0x00, 0x3C
  };
  const uint8_t response[] = {
      0x0A, MQTTSN_SLEEPRESP, 0x01, 0x12, 0x34,
      0x00, 0x00, 0x00, 0x3C, 0x00
  };
  uint8_t output[16];
  size_t written = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_sleepresp_view_t sleepresp;
  size_t consumed = 0u;

  assert(mqttsn_encode_sleepreq(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(written == sizeof(expected));
  assert(memcmp(output, expected, sizeof(expected)) == 0);

  assert(mqttsn_decode_packet(
      response, sizeof(response), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_sleepresp(&packet, &sleepresp) == MQTTSN_OK);
  assert(sleepresp.packet_identifier == 0x1234u);
  assert(sleepresp.has_sleep_duration == 1u);
  assert(sleepresp.sleep_duration == 60u);
  assert(sleepresp.has_reason_code == 1u);
  assert(sleepresp.reason_code == 0u);
}


static void test_length_boundaries_and_maximum_packet(void) {
  uint8_t short_body[253];
  uint8_t extended_body[254];
  uint8_t maximum_body[MQTTSN_MAX_PACKET_SIZE - 4u];
  uint8_t short_packet[255];
  uint8_t extended_packet[258];
  uint8_t *maximum_packet;
  mqttsn_packet_view_t view;
  size_t written = 0u;
  size_t consumed = 0u;

  memset(short_body, 0, sizeof(short_body));
  memset(extended_body, 0, sizeof(extended_body));
  memset(maximum_body, 0, sizeof(maximum_body));

  assert(mqttsn_encode_packet(
      MQTTSN_PUBLISH, short_body, sizeof(short_body),
      short_packet, sizeof(short_packet), &written) == MQTTSN_OK);
  assert(written == 255u);
  assert(short_packet[0] == 255u);
  assert(mqttsn_decode_packet(
      short_packet, written, &view, &consumed) == MQTTSN_OK);
  assert(view.header_length == 2u);

  assert(mqttsn_encode_packet(
      MQTTSN_PUBLISH, extended_body, sizeof(extended_body),
      extended_packet, sizeof(extended_packet), &written) == MQTTSN_OK);
  assert(written == 258u);
  assert(extended_packet[0] == 0x01u);
  assert(extended_packet[1] == 0x01u);
  assert(extended_packet[2] == 0x02u);
  assert(mqttsn_decode_packet(
      extended_packet, written, &view, &consumed) == MQTTSN_OK);
  assert(view.header_length == 4u);

  maximum_packet = (uint8_t *)malloc(MQTTSN_MAX_PACKET_SIZE);
  assert(maximum_packet != NULL);
  assert(mqttsn_encode_packet(
      MQTTSN_PUBLISH, maximum_body, sizeof(maximum_body),
      maximum_packet, MQTTSN_MAX_PACKET_SIZE, &written) == MQTTSN_OK);
  assert(written == MQTTSN_MAX_PACKET_SIZE);
  assert(mqttsn_decode_packet(
      maximum_packet, written, &view, &consumed) == MQTTSN_OK);
  assert(view.packet_length == MQTTSN_MAX_PACKET_SIZE);
  free(maximum_packet);
}

static void test_malformed_length_headers(void) {
  const uint8_t zero_length[] = {0x00};
  const uint8_t extended_one[] = {0x01};
  const uint8_t extended_two[] = {0x01, 0x00};
  const uint8_t extended_no_type[] = {0x01, 0x00, 0x04};
  const uint8_t extended_too_small[] = {0x01, 0x00, 0x03, MQTTSN_PINGREQ};
  mqttsn_packet_view_t view;
  size_t consumed = 0u;

  assert(mqttsn_decode_packet(
      zero_length, sizeof(zero_length), &view, &consumed) == MQTTSN_MALFORMED_PACKET);
  assert(mqttsn_decode_packet(
      extended_one, sizeof(extended_one), &view, &consumed) == MQTTSN_NEED_MORE);
  assert(mqttsn_decode_packet(
      extended_two, sizeof(extended_two), &view, &consumed) == MQTTSN_NEED_MORE);
  assert(mqttsn_decode_packet(
      extended_no_type, sizeof(extended_no_type), &view, &consumed) == MQTTSN_NEED_MORE);
  assert(mqttsn_decode_packet(
      extended_too_small, sizeof(extended_too_small), &view, &consumed) == MQTTSN_MALFORMED_PACKET);
}

static void test_connack_optional_fields_and_zero_identifier(void) {
  const uint8_t auth_connack[] = {
      0x12, MQTTSN_CONNACK,
      0x08,
      0x12, 0x34,
      0x00,
      0x03, 'p', 's', 'k',
      0x00, 0x02, 0x01, 0x02,
      'i', 'd', '4', '2'
  };
  const uint8_t zero_identifier[] = {
      0x06, MQTTSN_CONNACK, 0x00, 0x00, 0x00, 0x00
  };
  mqttsn_packet_view_t packet;
  mqttsn_connack_view_t connack;
  size_t consumed = 0u;

  assert(mqttsn_decode_packet(
      auth_connack, sizeof(auth_connack), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_connack(&packet, &connack) == MQTTSN_OK);
  assert(connack.has_authentication == 1u);
  assert(connack.authentication_method_length == 3u);
  assert(memcmp(connack.authentication_method, "psk", 3u) == 0);
  assert(connack.authentication_data_length == 2u);
  assert(connack.authentication_data[0] == 0x01u);
  assert(connack.authentication_data[1] == 0x02u);
  assert(connack.assigned_client_identifier_length == 4u);
  assert(memcmp(connack.assigned_client_identifier, "id42", 4u) == 0);

  assert(mqttsn_decode_packet(
      zero_identifier, sizeof(zero_identifier), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_connack(&packet, &connack) == MQTTSN_MALFORMED_PACKET);
}

static void test_publish_qos_and_alias_variants(void) {
  const uint8_t payload[] = {0x01, 0x02};
  mqttsn_publish_options_t options = {
      .qos = MQTTSN_QOS_1,
      .duplicate = 0u,
      .retain = 1u,
      .packet_identifier = 0x1234u,
      .topic = {
          .type = MQTTSN_TOPIC_SESSION_ALIAS,
          .alias = 42u,
          .name = NULL,
          .name_length = 0u
      },
      .payload = payload,
      .payload_length = sizeof(payload)
  };
  uint8_t output[32];
  size_t written = 0u;
  size_t consumed = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_publish_view_t publish;

  assert(mqttsn_encode_publish(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(mqttsn_decode_packet(
      output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_publish(&packet, &publish) == MQTTSN_OK);
  assert(publish.qos == MQTTSN_QOS_1);
  assert(publish.packet_identifier == 0x1234u);
  assert(publish.topic.type == MQTTSN_TOPIC_SESSION_ALIAS);
  assert(publish.topic.alias == 42u);
  assert(publish.retain == 1u);

  options.qos = MQTTSN_QOS_2;
  options.duplicate = 1u;
  options.retain = 0u;
  options.packet_identifier = 0xFFFFu;
  options.topic.type = MQTTSN_TOPIC_PREDEFINED_ALIAS;
  options.topic.alias = 7u;
  assert(mqttsn_encode_publish(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(mqttsn_decode_packet(
      output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_publish(&packet, &publish) == MQTTSN_OK);
  assert(publish.qos == MQTTSN_QOS_2);
  assert(publish.duplicate == 1u);
  assert(publish.topic.alias == 7u);
}

static void test_suback_zero_identifier_is_rejected(void) {
  const uint8_t suback[] = {
      0x05, MQTTSN_SUBACK, 0x00, 0x00, 0x00
  };
  mqttsn_packet_view_t packet;
  mqttsn_suback_view_t view;
  size_t consumed = 0u;

  assert(mqttsn_decode_packet(
      suback, sizeof(suback), &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_suback(&packet, &view) == MQTTSN_MALFORMED_PACKET);
}

static void test_ack_types_and_wakeup(void) {
  const mqttsn_packet_type_t ack_types[] = {
      MQTTSN_PUBACK, MQTTSN_PUBREC, MQTTSN_PUBREL,
      MQTTSN_PUBCOMP, MQTTSN_UNSUBACK
  };
  uint8_t output[16];
  size_t written = 0u;
  size_t consumed = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_ack_view_t ack;
  size_t i;

  for (i = 0u; i < sizeof(ack_types) / sizeof(ack_types[0]); i++) {
    assert(mqttsn_encode_ack(
        ack_types[i], 0x1234u, 1u, 0x80u,
        output, sizeof(output), &written) == MQTTSN_OK);
    assert(mqttsn_decode_packet(
        output, written, &packet, &consumed) == MQTTSN_OK);
    assert(mqttsn_decode_ack(&packet, &ack) == MQTTSN_OK);
    assert(ack.packet_identifier == 0x1234u);
    assert(ack.has_reason_code == 1u);
    assert(ack.reason_code == 0x80u);
  }

  assert(mqttsn_encode_wakeup(
      output, sizeof(output), &written) == MQTTSN_OK);
  assert(written == 2u);
  assert(output[0] == 0x02u);
  assert(output[1] == MQTTSN_WAKEUP);
}


static void test_disconnect_codec(void) {
  const uint8_t reason[] = "protocol error";
  mqttsn_disconnect_options_t options = {
      .has_packet_identifier = 1u,
      .packet_identifier = 0x1234u,
      .has_reason_code = 1u,
      .reason_code = 0x82u,
      .has_session_expiry_interval = 1u,
      .session_expiry_interval = 3600u,
      .reason_string = reason,
      .reason_string_length = sizeof(reason) - 1u
  };
  uint8_t output[64];
  size_t written = 0u;
  size_t consumed = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_disconnect_view_t decoded;

  assert(mqttsn_encode_disconnect(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(mqttsn_decode_packet(
      output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_disconnect(&packet, &decoded) == MQTTSN_OK);
  assert(decoded.has_packet_identifier == 1u);
  assert(decoded.packet_identifier == 0x1234u);
  assert(decoded.has_reason_code == 1u);
  assert(decoded.reason_code == 0x82u);
  assert(decoded.has_session_expiry_interval == 1u);
  assert(decoded.session_expiry_interval == 3600u);
  assert(decoded.reason_string_length == sizeof(reason) - 1u);
  assert(memcmp(decoded.reason_string, reason, sizeof(reason) - 1u) == 0);

  memset(&options, 0, sizeof(options));
  assert(mqttsn_encode_disconnect(
      &options, output, sizeof(output), &written) == MQTTSN_OK);
  assert(written == 3u);
  assert(output[0] == 0x03u);
  assert(output[1] == MQTTSN_DISCONNECT);
  assert(output[2] == 0x00u);

  {
    const uint8_t reserved[] = {0x03, MQTTSN_DISCONNECT, 0x80};
    assert(mqttsn_decode_packet(
        reserved, sizeof(reserved), &packet, &consumed) == MQTTSN_OK);
    assert(mqttsn_decode_disconnect(&packet, &decoded) == MQTTSN_MALFORMED_PACKET);
  }

  {
    const uint8_t zero_id[] = {
        0x05, MQTTSN_DISCONNECT, 0x01, 0x00, 0x00
    };
    assert(mqttsn_decode_packet(
        zero_id, sizeof(zero_id), &packet, &consumed) == MQTTSN_OK);
    assert(mqttsn_decode_disconnect(&packet, &decoded) == MQTTSN_MALFORMED_PACKET);
  }
}

int main(void) {
  test_packet_types();
  test_short_frame();
  test_extended_frame();
  test_incomplete_and_reserved();
  test_multiple_packets();
  test_utf8_validation();
  test_basic_connect();
  test_connack_decode();
  test_connack_rejects_reserved_flags_and_failed_session_present();
  test_topic_validation();
  test_publish_codec();
  test_subscribe_and_suback();
  test_ping_and_ack();
  test_sleep_codec();
  test_length_boundaries_and_maximum_packet();
  test_malformed_length_headers();
  test_connack_optional_fields_and_zero_identifier();
  test_publish_qos_and_alias_variants();
  test_suback_zero_identifier_is_rejected();
  test_ack_types_and_wakeup();
  test_disconnect_codec();
  return 0;
}
