#include "mqttsn/mqttsn.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
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
  return 0;
}
