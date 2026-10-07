#include "mqttsn/protection.h"

#include <string.h>

static int valid_scheme(
    const mqttsn_protection_provider_t *provider,
    uint8_t scheme) {
  if (provider == NULL || provider->supports == NULL ||
      !provider->supports(provider->user_data, scheme)) {
    return 0;
  }
  if ((scheme >= 0x05u && scheme <= 0x3Bu) ||
      (scheme >= 0x4Au && scheme <= 0xEFu)) {
    return 0;
  }
  return 1;
}

static mqttsn_status_t validate_provider(
    const mqttsn_protection_provider_t *provider) {
  if (provider == NULL ||
      provider->supports == NULL ||
      provider->authentication_only == NULL ||
      provider->authentication_tag_length == NULL ||
      provider->protected_packet_length == NULL ||
      provider->protect == NULL ||
      provider->unprotect == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  return MQTTSN_OK;
}

static mqttsn_status_t counter_length_code(
    size_t length,
    uint8_t *code) {
  if (code == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  switch (length) {
    case 0u:
      *code = 0u;
      return MQTTSN_OK;
    case 2u:
      *code = 1u;
      return MQTTSN_OK;
    case 4u:
      *code = 2u;
      return MQTTSN_OK;
    default:
      return MQTTSN_MALFORMED_PACKET;
  }
}

static mqttsn_status_t crypto_length_code(
    size_t length,
    uint8_t *code) {
  if (code == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  switch (length) {
    case 0u:
      *code = 0u;
      return MQTTSN_OK;
    case 2u:
      *code = 1u;
      return MQTTSN_OK;
    case 4u:
      *code = 2u;
      return MQTTSN_OK;
    case 12u:
      *code = 3u;
      return MQTTSN_OK;
    default:
      return MQTTSN_MALFORMED_PACKET;
  }
}

static size_t counter_length_from_code(uint8_t code) {
  switch (code) {
    case 0u:
      return 0u;
    case 1u:
      return 2u;
    case 2u:
      return 4u;
    default:
      return (size_t)-1;
  }
}

static size_t crypto_length_from_code(uint8_t code) {
  switch (code) {
    case 0u:
      return 0u;
    case 1u:
      return 2u;
    case 2u:
      return 4u;
    case 3u:
      return 12u;
    default:
      return (size_t)-1;
  }
}

static mqttsn_status_t validate_tag_rules(
    const mqttsn_protection_provider_t *provider,
    uint8_t scheme,
    uint8_t tag_code,
    size_t tag_length) {
  int authentication_only;

  if (tag_code == 0x02u || tag_code == 0x03u || tag_length == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  authentication_only =
      provider->authentication_only(provider->user_data, scheme);

  if (!authentication_only && tag_code != 0x01u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if (authentication_only && tag_code >= 0x04u &&
      tag_length != (size_t)tag_code * 2u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  return MQTTSN_OK;
}

static mqttsn_status_t validate_inner_packet(
    const uint8_t *packet_data,
    size_t packet_length) {
  mqttsn_packet_view_t packet;
  size_t consumed = 0u;
  mqttsn_status_t status;

  if (packet_data == NULL || packet_length == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  status = mqttsn_decode_packet(
      packet_data, packet_length, &packet, &consumed);
  if (status != MQTTSN_OK) {
    return status;
  }
  if (consumed != packet_length ||
      packet.type == MQTTSN_FORWARDER_ENCAPSULATION) {
    return MQTTSN_MALFORMED_PACKET;
  }

  return MQTTSN_OK;
}

static void write_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8);
  output[1] = (uint8_t)value;
}

mqttsn_status_t mqttsn_encode_protection(
    const mqttsn_protection_envelope_t *envelope,
    const mqttsn_protection_provider_t *provider,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t counter_code;
  uint8_t crypto_code;
  uint8_t tag_code;
  uint8_t flags;
  size_t tag_length;
  size_t protected_length;
  size_t body_length;
  size_t header_length;
  size_t packet_length;
  size_t offset;
  size_t prefix_length;
  size_t protected_written = 0u;
  size_t tag_written = 0u;
  mqttsn_protection_context_t context;
  mqttsn_status_t status;

  if (envelope == NULL || output == NULL || written == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  status = validate_provider(provider);
  if (status != MQTTSN_OK) {
    return status;
  }

  if (!valid_scheme(provider, envelope->scheme) ||
      envelope->sender_identifier == NULL ||
      envelope->sender_identifier_length != 8u ||
      envelope->random == NULL ||
      envelope->random_length != 4u ||
      (envelope->cryptographic_material == NULL &&
       envelope->cryptographic_material_length != 0u) ||
      (envelope->monotonic_counter == NULL &&
       envelope->monotonic_counter_length != 0u)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  status = counter_length_code(
      envelope->monotonic_counter_length, &counter_code);
  if (status != MQTTSN_OK) {
    return status;
  }

  status = crypto_length_code(
      envelope->cryptographic_material_length, &crypto_code);
  if (status != MQTTSN_OK) {
    return status;
  }

  tag_code = envelope->tag_length_code;
  if (tag_code > 0x0Fu) {
    return MQTTSN_MALFORMED_PACKET;
  }

  status = validate_inner_packet(
      envelope->mqttsn_packet, envelope->mqttsn_packet_length);
  if (status != MQTTSN_OK) {
    return status;
  }

  tag_length = provider->authentication_tag_length(
      provider->user_data, envelope->scheme, tag_code);
  protected_length = provider->protected_packet_length(
      provider->user_data,
      envelope->scheme,
      envelope->mqttsn_packet_length);

  status = validate_tag_rules(
      provider, envelope->scheme, tag_code, tag_length);
  if (status != MQTTSN_OK || protected_length == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body_length =
      14u +
      envelope->cryptographic_material_length +
      envelope->monotonic_counter_length +
      protected_length +
      tag_length;
  header_length = body_length <= 253u ? 2u : 4u;
  packet_length = body_length + header_length;

  if (packet_length > MQTTSN_MAX_PACKET_SIZE) {
    return MQTTSN_MALFORMED_PACKET;
  }
  if (output_capacity < packet_length) {
    return MQTTSN_BUFFER_TOO_SMALL;
  }

  offset = 0u;
  if (header_length == 2u) {
    output[offset++] = (uint8_t)packet_length;
  } else {
    output[offset++] = 0x01u;
    write_u16(output + offset, (uint16_t)packet_length);
    offset += 2u;
  }
  output[offset++] = MQTTSN_PROTECTION_ENCAPSULATION;

  flags = (uint8_t)((tag_code << 4) | (crypto_code << 2) | counter_code);
  output[offset++] = flags;
  output[offset++] = envelope->scheme;

  memcpy(output + offset, envelope->sender_identifier, 8u);
  offset += 8u;
  memcpy(output + offset, envelope->random, 4u);
  offset += 4u;

  if (envelope->cryptographic_material_length != 0u) {
    memcpy(
        output + offset,
        envelope->cryptographic_material,
        envelope->cryptographic_material_length);
    offset += envelope->cryptographic_material_length;
  }

  if (envelope->monotonic_counter_length != 0u) {
    memcpy(
        output + offset,
        envelope->monotonic_counter,
        envelope->monotonic_counter_length);
    offset += envelope->monotonic_counter_length;
  }

  prefix_length = offset;
  memset(&context, 0, sizeof(context));
  context.scheme = envelope->scheme;
  context.tag_length_code = tag_code;
  context.sender_identifier = envelope->sender_identifier;
  context.sender_identifier_length = 8u;
  context.random = envelope->random;
  context.random_length = 4u;
  context.cryptographic_material = envelope->cryptographic_material;
  context.cryptographic_material_length =
      envelope->cryptographic_material_length;
  context.monotonic_counter = envelope->monotonic_counter;
  context.monotonic_counter_length = envelope->monotonic_counter_length;
  context.authenticated_prefix = output;
  context.authenticated_prefix_length = prefix_length;

  status = provider->protect(
      provider->user_data,
      &context,
      envelope->mqttsn_packet,
      envelope->mqttsn_packet_length,
      output + offset,
      protected_length,
      &protected_written,
      output + offset + protected_length,
      tag_length,
      &tag_written);
  if (status != MQTTSN_OK) {
    return status;
  }

  if (protected_written != protected_length ||
      tag_written != tag_length) {
    return MQTTSN_MALFORMED_PACKET;
  }

  *written = packet_length;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_decode_protection(
    const uint8_t *input,
    size_t input_length,
    const mqttsn_protection_provider_t *provider,
    uint8_t *mqttsn_packet_output,
    size_t mqttsn_packet_capacity,
    size_t *mqttsn_packet_written,
    mqttsn_protection_envelope_t *envelope) {
  mqttsn_packet_view_t outer;
  size_t consumed = 0u;
  mqttsn_status_t status;
  const uint8_t *body;
  size_t body_length;
  size_t offset = 0u;
  uint8_t flags;
  uint8_t counter_code;
  uint8_t crypto_code;
  uint8_t tag_code;
  uint8_t scheme;
  size_t crypto_length;
  size_t counter_length;
  size_t tag_length;
  size_t protected_length;
  size_t prefix_length;
  mqttsn_protection_context_t context;

  if (input == NULL || mqttsn_packet_output == NULL ||
      mqttsn_packet_written == NULL || envelope == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  status = validate_provider(provider);
  if (status != MQTTSN_OK) {
    return status;
  }

  status = mqttsn_decode_packet(input, input_length, &outer, &consumed);
  if (status != MQTTSN_OK) {
    return status;
  }
  if (consumed != input_length ||
      outer.type != MQTTSN_PROTECTION_ENCAPSULATION ||
      outer.body_length < 14u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body = outer.body;
  body_length = outer.body_length;

  flags = body[offset++];
  counter_code = (uint8_t)(flags & 0x03u);
  crypto_code = (uint8_t)((flags >> 2) & 0x03u);
  tag_code = (uint8_t)((flags >> 4) & 0x0Fu);

  if (counter_code == 0x03u ||
      tag_code == 0x02u ||
      tag_code == 0x03u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  scheme = body[offset++];
  if (!valid_scheme(provider, scheme)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  crypto_length = crypto_length_from_code(crypto_code);
  counter_length = counter_length_from_code(counter_code);
  if (crypto_length == (size_t)-1 ||
      counter_length == (size_t)-1 ||
      body_length < 14u + crypto_length + counter_length) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(envelope, 0, sizeof(*envelope));
  envelope->scheme = scheme;
  envelope->tag_length_code = tag_code;

  envelope->sender_identifier = body + offset;
  envelope->sender_identifier_length = 8u;
  offset += 8u;

  envelope->random = body + offset;
  envelope->random_length = 4u;
  offset += 4u;

  envelope->cryptographic_material = body + offset;
  envelope->cryptographic_material_length = crypto_length;
  offset += crypto_length;

  envelope->monotonic_counter = body + offset;
  envelope->monotonic_counter_length = counter_length;
  offset += counter_length;

  tag_length = provider->authentication_tag_length(
      provider->user_data, scheme, tag_code);
  status = validate_tag_rules(
      provider, scheme, tag_code, tag_length);
  if (status != MQTTSN_OK ||
      body_length - offset <= tag_length) {
    return MQTTSN_MALFORMED_PACKET;
  }

  protected_length = body_length - offset - tag_length;
  prefix_length = outer.header_length + offset;

  memset(&context, 0, sizeof(context));
  context.scheme = scheme;
  context.tag_length_code = tag_code;
  context.sender_identifier = envelope->sender_identifier;
  context.sender_identifier_length = 8u;
  context.random = envelope->random;
  context.random_length = 4u;
  context.cryptographic_material = envelope->cryptographic_material;
  context.cryptographic_material_length = crypto_length;
  context.monotonic_counter = envelope->monotonic_counter;
  context.monotonic_counter_length = counter_length;
  context.authenticated_prefix = input;
  context.authenticated_prefix_length = prefix_length;

  status = provider->unprotect(
      provider->user_data,
      &context,
      body + offset,
      protected_length,
      body + offset + protected_length,
      tag_length,
      mqttsn_packet_output,
      mqttsn_packet_capacity,
      mqttsn_packet_written);
  if (status != MQTTSN_OK) {
    return status;
  }

  status = validate_inner_packet(
      mqttsn_packet_output, *mqttsn_packet_written);
  if (status != MQTTSN_OK) {
    return status;
  }

  envelope->mqttsn_packet = mqttsn_packet_output;
  envelope->mqttsn_packet_length = *mqttsn_packet_written;
  return MQTTSN_OK;
}
