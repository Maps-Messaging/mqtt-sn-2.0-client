#include "mqttsn/mqttsn.h"

#include <string.h>

int mqttsn_packet_type_is_defined(uint8_t type) {
  return (type >= MQTTSN_CONNECT && type <= MQTTSN_GWINFO) ||
         type == MQTTSN_FORWARDER_ENCAPSULATION ||
         type == MQTTSN_CONNECTION_ENCAPSULATION ||
         type == MQTTSN_PROTECTION_ENCAPSULATION;
}

static mqttsn_status_t decode_length(
    const uint8_t *input,
    size_t input_length,
    size_t *packet_length,
    size_t *length_field_size) {
  if (input == NULL || packet_length == NULL || length_field_size == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (input_length < 1u) {
    return MQTTSN_NEED_MORE;
  }

  if (input[0] == 0x01u) {
    if (input_length < 3u) {
      return MQTTSN_NEED_MORE;
    }
    *packet_length = ((size_t)input[1] << 8u) | (size_t)input[2];
    *length_field_size = 3u;
    if (*packet_length < 4u) {
      return MQTTSN_MALFORMED_PACKET;
    }
  } else {
    *packet_length = input[0];
    *length_field_size = 1u;
    if (*packet_length < 2u) {
      return MQTTSN_MALFORMED_PACKET;
    }
  }

  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_decode_packet(
    const uint8_t *input,
    size_t input_length,
    mqttsn_packet_view_t *packet,
    size_t *consumed) {
  size_t packet_length = 0u;
  size_t length_field_size = 0u;
  size_t header_length;
  mqttsn_status_t status;

  if (input == NULL || packet == NULL || consumed == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  *consumed = 0u;

  status = decode_length(input, input_length, &packet_length, &length_field_size);
  if (status != MQTTSN_OK) {
    return status;
  }

  header_length = length_field_size + 1u;
  if (input_length < header_length || input_length < packet_length) {
    return MQTTSN_NEED_MORE;
  }

  if (!mqttsn_packet_type_is_defined(input[length_field_size])) {
    return MQTTSN_RESERVED_TYPE;
  }

  packet->type = (mqttsn_packet_type_t)input[length_field_size];
  packet->body = input + header_length;
  packet->body_length = packet_length - header_length;
  packet->packet_length = packet_length;
  packet->header_length = header_length;
  *consumed = packet_length;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_encode_packet(
    mqttsn_packet_type_t type,
    const uint8_t *body,
    size_t body_length,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  size_t packet_length;
  size_t header_length;

  if (output == NULL || written == NULL || (body == NULL && body_length != 0u)) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  *written = 0u;

  if (!mqttsn_packet_type_is_defined((uint8_t)type)) {
    return MQTTSN_RESERVED_TYPE;
  }

  if (body_length <= 253u) {
    header_length = 2u;
    packet_length = body_length + header_length;
  } else {
    header_length = 4u;
    if (body_length > (MQTTSN_MAX_PACKET_SIZE - header_length)) {
      return MQTTSN_MALFORMED_PACKET;
    }
    packet_length = body_length + header_length;
  }

  if (output_capacity < packet_length) {
    return MQTTSN_BUFFER_TOO_SMALL;
  }

  if (header_length == 2u) {
    output[0] = (uint8_t)packet_length;
    output[1] = (uint8_t)type;
  } else {
    output[0] = 0x01u;
    output[1] = (uint8_t)((packet_length >> 8u) & 0xFFu);
    output[2] = (uint8_t)(packet_length & 0xFFu);
    output[3] = (uint8_t)type;
  }

  if (body_length != 0u) {
    memcpy(output + header_length, body, body_length);
  }
  *written = packet_length;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_process_input(
    const uint8_t *input,
    size_t input_length,
    mqttsn_packet_handler_t handler,
    void *context,
    size_t *consumed) {
  size_t offset = 0u;

  if (input == NULL || handler == NULL || consumed == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  *consumed = 0u;

  while (offset < input_length) {
    mqttsn_packet_view_t packet;
    size_t packet_consumed = 0u;
    mqttsn_status_t status = mqttsn_decode_packet(
        input + offset,
        input_length - offset,
        &packet,
        &packet_consumed);

    if (status == MQTTSN_NEED_MORE) {
      *consumed = offset;
      return status;
    }
    if (status != MQTTSN_OK) {
      *consumed = offset;
      return status;
    }

    status = handler(context, &packet);
    if (status != MQTTSN_OK) {
      *consumed = offset;
      return status;
    }
    offset += packet_consumed;
  }

  *consumed = offset;
  return MQTTSN_OK;
}
