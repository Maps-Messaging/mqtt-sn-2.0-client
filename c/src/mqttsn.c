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


static uint16_t read_u16(const uint8_t *data) {
  return (uint16_t)(((uint16_t)data[0] << 8u) | (uint16_t)data[1]);
}

static uint32_t read_u32(const uint8_t *data) {
  return ((uint32_t)data[0] << 24u) |
         ((uint32_t)data[1] << 16u) |
         ((uint32_t)data[2] << 8u) |
         (uint32_t)data[3];
}

static void write_u16(uint8_t *data, uint16_t value) {
  data[0] = (uint8_t)((value >> 8u) & 0xFFu);
  data[1] = (uint8_t)(value & 0xFFu);
}

int mqttsn_utf8_is_valid(const uint8_t *data, size_t length) {
  size_t i = 0u;

  if (data == NULL && length != 0u) {
    return 0;
  }

  while (i < length) {
    uint8_t first = data[i];
    uint32_t codepoint;
    size_t continuation_count;
    size_t j;

    if (first == 0u) {
      return 0;
    }
    if (first <= 0x7Fu) {
      i++;
      continue;
    }
    if (first >= 0xC2u && first <= 0xDFu) {
      codepoint = (uint32_t)(first & 0x1Fu);
      continuation_count = 1u;
    } else if (first >= 0xE0u && first <= 0xEFu) {
      codepoint = (uint32_t)(first & 0x0Fu);
      continuation_count = 2u;
    } else if (first >= 0xF0u && first <= 0xF4u) {
      codepoint = (uint32_t)(first & 0x07u);
      continuation_count = 3u;
    } else {
      return 0;
    }

    if (i + continuation_count >= length) {
      return 0;
    }

    for (j = 1u; j <= continuation_count; j++) {
      uint8_t next = data[i + j];
      if ((next & 0xC0u) != 0x80u) {
        return 0;
      }
      codepoint = (codepoint << 6u) | (uint32_t)(next & 0x3Fu);
    }

    if ((continuation_count == 2u && codepoint < 0x800u) ||
        (continuation_count == 3u && codepoint < 0x10000u) ||
        codepoint > 0x10FFFFu ||
        (codepoint >= 0xD800u && codepoint <= 0xDFFFu)) {
      return 0;
    }

    i += continuation_count + 1u;
  }

  return 1;
}

mqttsn_status_t mqttsn_encode_connect(
    const mqttsn_connect_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  size_t body_length;
  size_t header_length;
  size_t packet_length;
  size_t offset;
  uint8_t flags = 0u;

  if (options == NULL || output == NULL || written == NULL ||
      (options->client_identifier == NULL &&
       options->client_identifier_length != 0u)) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  *written = 0u;

  if (options->packet_identifier == 0u ||
      options->keep_alive == 0u ||
      (options->maximum_packet_size != 0u &&
       options->maximum_packet_size < 10u)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if (!mqttsn_utf8_is_valid(
          options->client_identifier, options->client_identifier_length)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if (options->client_identifier_length > MQTTSN_MAX_PACKET_SIZE - 12u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body_length = 8u + options->client_identifier_length;
  header_length = body_length <= 253u ? 2u : 4u;
  packet_length = body_length + header_length;
  if (packet_length > MQTTSN_MAX_PACKET_SIZE) {
    return MQTTSN_MALFORMED_PACKET;
  }
  if (output_capacity < packet_length) {
    return MQTTSN_BUFFER_TOO_SMALL;
  }

  if (header_length == 2u) {
    output[0] = (uint8_t)packet_length;
    output[1] = (uint8_t)MQTTSN_CONNECT;
  } else {
    output[0] = 0x01u;
    output[1] = (uint8_t)((packet_length >> 8u) & 0xFFu);
    output[2] = (uint8_t)(packet_length & 0xFFu);
    output[3] = (uint8_t)MQTTSN_CONNECT;
  }

  if (options->clean_start) {
    flags |= 0x01u;
  }
  if (options->allow_network_address_changes) {
    flags |= 0x20u;
  }
  if (options->allow_server_suggested_values) {
    flags |= 0x40u;
  }

  offset = header_length;
  output[offset++] = flags;
  write_u16(output + offset, options->packet_identifier);
  offset += 2u;
  output[offset++] = 0x02u;
  write_u16(output + offset, options->keep_alive);
  offset += 2u;
  write_u16(output + offset, options->maximum_packet_size);
  offset += 2u;

  if (options->client_identifier_length != 0u) {
    memcpy(
        output + offset,
        options->client_identifier,
        options->client_identifier_length);
    offset += options->client_identifier_length;
  }

  *written = offset;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_decode_connack(
    const mqttsn_packet_view_t *packet,
    mqttsn_connack_view_t *connack) {
  const uint8_t *body;
  size_t length;
  size_t offset = 0u;
  uint8_t flags;

  if (packet == NULL || connack == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (packet->type != MQTTSN_CONNACK) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body = packet->body;
  length = packet->body_length;
  if (length < 4u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(connack, 0, sizeof(*connack));
  flags = body[offset++];
  if ((flags & 0xF0u) != 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  connack->session_present = (uint8_t)(flags & 0x01u);
  connack->packet_identifier = read_u16(body + offset);
  offset += 2u;
  connack->reason_code = body[offset++];

  if (connack->reason_code != 0u && connack->session_present != 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if ((flags & 0x02u) != 0u) {
    if (length - offset < 4u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    connack->has_session_expiry_interval = 1u;
    connack->session_expiry_interval = read_u32(body + offset);
    offset += 4u;
  }

  if ((flags & 0x04u) != 0u) {
    if (length - offset < 2u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    connack->has_server_keep_alive = 1u;
    connack->server_keep_alive = read_u16(body + offset);
    if (connack->server_keep_alive == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    offset += 2u;
  }

  if ((flags & 0x08u) != 0u) {
    size_t method_length;
    size_t data_length;

    if (length - offset < 1u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    method_length = body[offset++];
    if (length - offset < method_length + 2u) {
      return MQTTSN_MALFORMED_PACKET;
    }

    connack->has_authentication = 1u;
    connack->authentication_method = body + offset;
    connack->authentication_method_length = method_length;
    if (!mqttsn_utf8_is_valid(
            connack->authentication_method,
            connack->authentication_method_length)) {
      return MQTTSN_MALFORMED_PACKET;
    }
    offset += method_length;

    data_length = read_u16(body + offset);
    offset += 2u;
    if (length - offset < data_length) {
      return MQTTSN_MALFORMED_PACKET;
    }
    connack->authentication_data = body + offset;
    connack->authentication_data_length = data_length;
    offset += data_length;
  }

  connack->assigned_client_identifier = body + offset;
  connack->assigned_client_identifier_length = length - offset;
  if (!mqttsn_utf8_is_valid(
          connack->assigned_client_identifier,
          connack->assigned_client_identifier_length)) {
    return MQTTSN_MALFORMED_PACKET;
  }

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
