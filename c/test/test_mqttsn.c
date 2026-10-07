#include "mqttsn/mqttsn.h"
#include "mqttsn/packets.h"
#include "mqttsn/protection.h"

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


static void test_auth_codec(void) {
  const uint8_t method[] = "psk";
  const uint8_t data[] = {0x01, 0x02, 0x03};
  mqttsn_auth_t auth = {
      .packet_identifier = 0x1234u,
      .reason_code = 0x18u,
      .authentication_method = method,
      .authentication_method_length = sizeof(method) - 1u,
      .authentication_data = data,
      .authentication_data_length = sizeof(data)
  };
  uint8_t output[32];
  size_t written = 0u;
  size_t consumed = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_auth_t decoded;

  assert(mqttsn_encode_auth(
      &auth, output, sizeof(output), &written) == MQTTSN_OK);
  assert(mqttsn_decode_packet(
      output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_auth(&packet, &decoded) == MQTTSN_OK);
  assert(decoded.packet_identifier == 0x1234u);
  assert(decoded.reason_code == 0x18u);
  assert(decoded.authentication_method_length == 3u);
  assert(memcmp(decoded.authentication_method, "psk", 3u) == 0);
  assert(decoded.authentication_data_length == 3u);
  assert(memcmp(decoded.authentication_data, data, 3u) == 0);

  {
    const uint8_t zero_id[] = {
        0x06, MQTTSN_AUTH, 0x00, 0x00, 0x18, 0x00
    };
    assert(mqttsn_decode_packet(
        zero_id, sizeof(zero_id), &packet, &consumed) == MQTTSN_OK);
    assert(mqttsn_decode_auth(&packet, &decoded) == MQTTSN_MALFORMED_PACKET);
  }

  {
    const uint8_t truncated[] = {
        0x07, MQTTSN_AUTH, 0x12, 0x34, 0x18, 0x03, 'p'
    };
    assert(mqttsn_decode_packet(
        truncated, sizeof(truncated), &packet, &consumed) == MQTTSN_OK);
    assert(mqttsn_decode_auth(&packet, &decoded) == MQTTSN_MALFORMED_PACKET);
  }
}


static void test_pubwos_and_gateway_discovery(void) {
  const uint8_t topic[] = "a/b";
  const uint8_t payload[] = {'x'};
  const uint8_t network_info[] = {0x01, 0x02};
  const uint8_t gateway_address[] = {0xC0, 0xA8, 0x01, 0x01};
  mqttsn_pubwos_t pubwos = {
      .retain = 0u,
      .topic = {
          .type = MQTTSN_TOPIC_NAME,
          .alias = 0u,
          .name = topic,
          .name_length = sizeof(topic) - 1u
      },
      .payload = payload,
      .payload_length = sizeof(payload)
  };
  mqttsn_advertise_t advertise = {
      .gateway_identifier = 7u,
      .duration = 60u
  };
  mqttsn_searchgw_t searchgw = {
      .additional_network_information = network_info,
      .additional_network_information_length = sizeof(network_info)
  };
  mqttsn_gwinfo_t gwinfo = {
      .gateway_identifier = 7u,
      .gateway_address = gateway_address,
      .gateway_address_length = sizeof(gateway_address)
  };
  uint8_t output[64];
  size_t written = 0u;
  size_t consumed = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_pubwos_t decoded_pubwos;
  mqttsn_advertise_t decoded_advertise;
  mqttsn_searchgw_t decoded_searchgw;
  mqttsn_gwinfo_t decoded_gwinfo;

  assert(mqttsn_encode_pubwos(
      &pubwos, output, sizeof(output), &written) == MQTTSN_OK);
  {
    const uint8_t expected[] = {
        0x09, MQTTSN_PUBWOS, 0x03, 0x00, 0x03, 'a', '/', 'b', 'x'
    };
    assert(written == sizeof(expected));
    assert(memcmp(output, expected, sizeof(expected)) == 0);
  }
  assert(mqttsn_decode_packet(output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_pubwos(&packet, &decoded_pubwos) == MQTTSN_OK);
  assert(decoded_pubwos.topic.type == MQTTSN_TOPIC_NAME);
  assert(decoded_pubwos.topic.name_length == 3u);
  assert(decoded_pubwos.payload_length == 1u);

  pubwos.topic.type = MQTTSN_TOPIC_SESSION_ALIAS;
  pubwos.topic.alias = 1u;
  pubwos.topic.name = NULL;
  pubwos.topic.name_length = 0u;
  assert(mqttsn_encode_pubwos(
      &pubwos, output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);

  assert(mqttsn_encode_advertise(
      &advertise, output, sizeof(output), &written) == MQTTSN_OK);
  {
    const uint8_t expected[] = {0x05, MQTTSN_ADVERTISE, 0x07, 0x00, 0x3C};
    assert(written == sizeof(expected));
    assert(memcmp(output, expected, sizeof(expected)) == 0);
  }
  assert(mqttsn_decode_packet(output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_advertise(&packet, &decoded_advertise) == MQTTSN_OK);
  assert(decoded_advertise.gateway_identifier == 7u);
  assert(decoded_advertise.duration == 60u);

  assert(mqttsn_encode_searchgw(
      &searchgw, output, sizeof(output), &written) == MQTTSN_OK);
  {
    const uint8_t expected[] = {0x04, MQTTSN_SEARCHGW, 0x01, 0x02};
    assert(written == sizeof(expected));
    assert(memcmp(output, expected, sizeof(expected)) == 0);
  }
  assert(mqttsn_decode_packet(output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_searchgw(&packet, &decoded_searchgw) == MQTTSN_OK);
  assert(decoded_searchgw.additional_network_information_length == 2u);

  assert(mqttsn_encode_gwinfo(
      &gwinfo, output, sizeof(output), &written) == MQTTSN_OK);
  {
    const uint8_t expected[] = {
        0x07, MQTTSN_GWINFO, 0x07, 0xC0, 0xA8, 0x01, 0x01
    };
    assert(written == sizeof(expected));
    assert(memcmp(output, expected, sizeof(expected)) == 0);
  }
  assert(mqttsn_decode_packet(output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_gwinfo(&packet, &decoded_gwinfo) == MQTTSN_OK);
  assert(decoded_gwinfo.gateway_identifier == 7u);
  assert(decoded_gwinfo.gateway_address_length == 4u);
}


static void test_connection_and_forwarder_encapsulation(void) {
  const uint8_t client_id[] = "client1";
  const uint8_t addressing[] = {0x01, 0x02};
  const uint8_t inner[] = {0x04, MQTTSN_PINGREQ, 0x12, 0x34};
  const uint8_t disallowed_inner[] = {
      0x06, MQTTSN_CONNACK, 0x00, 0x12, 0x34, 0x00
  };
  mqttsn_connection_encapsulation_t connection = {
      .client_identifier = client_id,
      .client_identifier_length = sizeof(client_id) - 1u,
      .mqttsn_packet = inner,
      .mqttsn_packet_length = sizeof(inner)
  };
  mqttsn_forwarder_encapsulation_t forwarder = {
      .client_addressing_information = addressing,
      .client_addressing_information_length = sizeof(addressing),
      .mqttsn_packet = inner,
      .mqttsn_packet_length = sizeof(inner)
  };
  uint8_t output[64];
  size_t written = 0u;
  size_t consumed = 0u;
  mqttsn_packet_view_t packet;
  mqttsn_connection_encapsulation_t decoded_connection;
  mqttsn_forwarder_encapsulation_t decoded_forwarder;

  assert(mqttsn_encode_connection_encapsulation(
      &connection, output, sizeof(output), &written) == MQTTSN_OK);
  {
    const uint8_t expected[] = {
        0x0F, MQTTSN_CONNECTION_ENCAPSULATION,
        0x00, 0x07,
        'c', 'l', 'i', 'e', 'n', 't', '1',
        0x04, MQTTSN_PINGREQ, 0x12, 0x34
    };
    assert(written == sizeof(expected));
    assert(memcmp(output, expected, sizeof(expected)) == 0);
  }
  assert(mqttsn_decode_packet(output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_connection_encapsulation(
      &packet, &decoded_connection) == MQTTSN_OK);
  assert(decoded_connection.client_identifier_length == 7u);
  assert(decoded_connection.mqttsn_packet_length == sizeof(inner));

  connection.mqttsn_packet = disallowed_inner;
  connection.mqttsn_packet_length = sizeof(disallowed_inner);
  assert(mqttsn_encode_connection_encapsulation(
      &connection, output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);

  assert(mqttsn_encode_forwarder_encapsulation(
      &forwarder, output, sizeof(output), &written) == MQTTSN_OK);
  {
    const uint8_t expected[] = {
        0x09, MQTTSN_FORWARDER_ENCAPSULATION,
        0x02, 0x01, 0x02,
        0x04, MQTTSN_PINGREQ, 0x12, 0x34
    };
    assert(written == sizeof(expected));
    assert(memcmp(output, expected, sizeof(expected)) == 0);
  }
  assert(mqttsn_decode_packet(output, written, &packet, &consumed) == MQTTSN_OK);
  assert(mqttsn_decode_forwarder_encapsulation(
      &packet, &decoded_forwarder) == MQTTSN_OK);
  assert(decoded_forwarder.client_addressing_information_length == 2u);
  assert(decoded_forwarder.mqttsn_packet_length == sizeof(inner));

  {
    const uint8_t missing_inner[] = {
        0x04, MQTTSN_FORWARDER_ENCAPSULATION, 0x01, 0x55
    };
    assert(mqttsn_decode_packet(
        missing_inner, sizeof(missing_inner), &packet, &consumed) == MQTTSN_OK);
    assert(mqttsn_decode_forwarder_encapsulation(
        &packet, &decoded_forwarder) == MQTTSN_MALFORMED_PACKET);
  }
}


static int protection_supports(void *user_data, uint8_t scheme) {
  (void)user_data;
  return scheme == 0x3Cu || scheme == 0x40u;
}

static int protection_auth_only(void *user_data, uint8_t scheme) {
  (void)user_data;
  return scheme == 0x3Cu;
}

static size_t protection_tag_length(
    void *user_data,
    uint8_t scheme,
    uint8_t tag_code) {
  (void)user_data;
  if (tag_code == 0u) {
    return 6u;
  }
  if (tag_code == 1u) {
    return scheme == 0x40u ? 8u : 16u;
  }
  if (tag_code >= 4u) {
    return (size_t)tag_code * 2u;
  }
  return 0u;
}

static size_t protection_packet_length(
    void *user_data,
    uint8_t scheme,
    size_t mqttsn_packet_length) {
  (void)user_data;
  (void)scheme;
  return mqttsn_packet_length;
}

static mqttsn_status_t protection_protect(
    void *user_data,
    const mqttsn_protection_context_t *context,
    const uint8_t *mqttsn_packet,
    size_t mqttsn_packet_length,
    uint8_t *protected_packet,
    size_t protected_packet_capacity,
    size_t *protected_packet_written,
    uint8_t *authentication_tag,
    size_t authentication_tag_capacity,
    size_t *authentication_tag_written) {
  size_t tag_length;
  uint8_t tag_value;

  (void)user_data;
  if (context == NULL || mqttsn_packet == NULL ||
      protected_packet == NULL || protected_packet_written == NULL ||
      authentication_tag == NULL || authentication_tag_written == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  tag_length = protection_tag_length(
      NULL, context->scheme, context->tag_length_code);
  if (protected_packet_capacity < mqttsn_packet_length ||
      authentication_tag_capacity < tag_length) {
    return MQTTSN_BUFFER_TOO_SMALL;
  }

  memcpy(protected_packet, mqttsn_packet, mqttsn_packet_length);
  tag_value = (uint8_t)context->authenticated_prefix_length;
  memset(authentication_tag, tag_value, tag_length);
  *protected_packet_written = mqttsn_packet_length;
  *authentication_tag_written = tag_length;
  return MQTTSN_OK;
}

static mqttsn_status_t protection_unprotect(
    void *user_data,
    const mqttsn_protection_context_t *context,
    const uint8_t *protected_packet,
    size_t protected_packet_length,
    const uint8_t *authentication_tag,
    size_t authentication_tag_length,
    uint8_t *mqttsn_packet,
    size_t mqttsn_packet_capacity,
    size_t *mqttsn_packet_written) {
  size_t i;
  uint8_t expected;

  (void)user_data;
  if (context == NULL || protected_packet == NULL ||
      authentication_tag == NULL || mqttsn_packet == NULL ||
      mqttsn_packet_written == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (mqttsn_packet_capacity < protected_packet_length) {
    return MQTTSN_BUFFER_TOO_SMALL;
  }

  expected = (uint8_t)context->authenticated_prefix_length;
  for (i = 0u; i < authentication_tag_length; i++) {
    if (authentication_tag[i] != expected) {
      return MQTTSN_MALFORMED_PACKET;
    }
  }

  memcpy(mqttsn_packet, protected_packet, protected_packet_length);
  *mqttsn_packet_written = protected_packet_length;
  return MQTTSN_OK;
}

static mqttsn_protection_provider_t test_protection_provider(void) {
  mqttsn_protection_provider_t provider = {
      .user_data = NULL,
      .supports = protection_supports,
      .authentication_only = protection_auth_only,
      .authentication_tag_length = protection_tag_length,
      .protected_packet_length = protection_packet_length,
      .protect = protection_protect,
      .unprotect = protection_unprotect
  };
  return provider;
}

static void test_protection_envelope(void) {
  const uint8_t sender_id[8] = {1,2,3,4,5,6,7,8};
  const uint8_t random[4] = {9,10,11,12};
  const uint8_t crypto[2] = {0x21, 0x22};
  const uint8_t counter[2] = {0x00, 0x01};
  const uint8_t inner[] = {0x04, MQTTSN_PINGREQ, 0x12, 0x34};
  mqttsn_protection_provider_t provider = test_protection_provider();
  mqttsn_protection_envelope_t envelope = {
      .scheme = 0x3Cu,
      .tag_length_code = 0x04u,
      .sender_identifier = sender_id,
      .sender_identifier_length = sizeof(sender_id),
      .random = random,
      .random_length = sizeof(random),
      .cryptographic_material = crypto,
      .cryptographic_material_length = sizeof(crypto),
      .monotonic_counter = counter,
      .monotonic_counter_length = sizeof(counter),
      .mqttsn_packet = inner,
      .mqttsn_packet_length = sizeof(inner)
  };
  uint8_t encoded[128];
  size_t encoded_length = 0u;
  uint8_t decoded_inner[64];
  size_t decoded_inner_length = 0u;
  mqttsn_protection_envelope_t decoded;

  assert(mqttsn_encode_protection(
      &envelope, &provider,
      encoded, sizeof(encoded), &encoded_length) == MQTTSN_OK);

  assert(mqttsn_decode_protection(
      encoded, encoded_length, &provider,
      decoded_inner, sizeof(decoded_inner), &decoded_inner_length,
      &decoded) == MQTTSN_OK);

  assert(decoded.scheme == 0x3Cu);
  assert(decoded.tag_length_code == 0x04u);
  assert(decoded.sender_identifier_length == 8u);
  assert(decoded.random_length == 4u);
  assert(decoded.cryptographic_material_length == 2u);
  assert(decoded.monotonic_counter_length == 2u);
  assert(decoded_inner_length == sizeof(inner));
  assert(memcmp(decoded_inner, inner, sizeof(inner)) == 0);

  encoded[encoded_length - 1u] ^= 0x01u;
  assert(mqttsn_decode_protection(
      encoded, encoded_length, &provider,
      decoded_inner, sizeof(decoded_inner), &decoded_inner_length,
      &decoded) == MQTTSN_MALFORMED_PACKET);
}

static void test_protection_rejects_forwarder_and_bad_tag_rules(void) {
  const uint8_t sender_id[8] = {0};
  const uint8_t random[4] = {0};
  const uint8_t forwarder[] = {
      0x07, MQTTSN_FORWARDER_ENCAPSULATION,
      0x01, 0x55,
      0x03, MQTTSN_DISCONNECT, 0x00
  };
  mqttsn_protection_provider_t provider = test_protection_provider();
  mqttsn_protection_envelope_t envelope = {
      .scheme = 0x3Cu,
      .tag_length_code = 0x04u,
      .sender_identifier = sender_id,
      .sender_identifier_length = sizeof(sender_id),
      .random = random,
      .random_length = sizeof(random),
      .cryptographic_material = NULL,
      .cryptographic_material_length = 0u,
      .monotonic_counter = NULL,
      .monotonic_counter_length = 0u,
      .mqttsn_packet = forwarder,
      .mqttsn_packet_length = sizeof(forwarder)
  };
  uint8_t output[128];
  size_t written = 0u;

  assert(mqttsn_encode_protection(
      &envelope, &provider,
      output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);

  envelope.scheme = 0x40u;
  envelope.tag_length_code = 0x04u;
  {
    const uint8_t ping[] = {0x04, MQTTSN_PINGREQ, 0x00, 0x01};
    envelope.mqttsn_packet = ping;
    envelope.mqttsn_packet_length = sizeof(ping);
    assert(mqttsn_encode_protection(
        &envelope, &provider,
        output, sizeof(output), &written) == MQTTSN_MALFORMED_PACKET);
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
  test_auth_codec();
  test_pubwos_and_gateway_discovery();
  test_connection_and_forwarder_encapsulation();
  test_protection_envelope();
  test_protection_rejects_forwarder_and_bad_tag_rules();
  return 0;
}
