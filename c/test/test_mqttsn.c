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

int main(void) {
  test_packet_types();
  test_short_frame();
  test_extended_frame();
  test_incomplete_and_reserved();
  test_multiple_packets();
  return 0;
}
