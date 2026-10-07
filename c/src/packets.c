#include "mqttsn/packets.h"

#include <string.h>

static uint16_t read_u16_packet(const uint8_t *data) {
  return (uint16_t)(((uint16_t)data[0] << 8u) | (uint16_t)data[1]);
}

static uint32_t read_u32_packet(const uint8_t *data) {
  return ((uint32_t)data[0] << 24u) |
         ((uint32_t)data[1] << 16u) |
         ((uint32_t)data[2] << 8u) |
         (uint32_t)data[3];
}

static void write_u16_packet(uint8_t *data, uint16_t value) {
  data[0] = (uint8_t)((value >> 8u) & 0xFFu);
  data[1] = (uint8_t)(value & 0xFFu);
}

static void write_u32_packet(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)((value >> 24u) & 0xFFu);
  data[1] = (uint8_t)((value >> 16u) & 0xFFu);
  data[2] = (uint8_t)((value >> 8u) & 0xFFu);
  data[3] = (uint8_t)(value & 0xFFu);
}

static int topic_type_is_valid(mqttsn_topic_type_t type) {
  return type == MQTTSN_TOPIC_SESSION_ALIAS ||
         type == MQTTSN_TOPIC_PREDEFINED_ALIAS ||
         type == MQTTSN_TOPIC_NAME;
}

static int topic_ref_is_valid(
    const mqttsn_topic_ref_t *topic,
    int filter) {
  if (topic == NULL || !topic_type_is_valid(topic->type)) {
    return 0;
  }

  if (topic->type == MQTTSN_TOPIC_NAME) {
    if (topic->name == NULL && topic->name_length != 0u) {
      return 0;
    }
    return filter
        ? mqttsn_topic_filter_is_valid(topic->name, topic->name_length)
        : mqttsn_topic_name_is_valid(topic->name, topic->name_length);
  }

  return topic->alias != 0u && topic->name_length == 0u;
}

static int ack_type_is_valid(mqttsn_packet_type_t type) {
  return type == MQTTSN_PUBACK ||
         type == MQTTSN_PUBREC ||
         type == MQTTSN_PUBREL ||
         type == MQTTSN_PUBCOMP ||
         type == MQTTSN_UNSUBACK;
}

mqttsn_status_t mqttsn_encode_register(
    uint16_t packet_identifier,
    const uint8_t *topic_name,
    size_t topic_name_length,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t prefix[3];
  mqttsn_buffer_t parts[2];

  if (packet_identifier == 0u ||
      !mqttsn_topic_name_is_valid(topic_name, topic_name_length)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  prefix[0] = 0u;
  write_u16_packet(prefix + 1u, packet_identifier);
  parts[0].data = prefix;
  parts[0].length = sizeof(prefix);
  parts[1].data = topic_name;
  parts[1].length = topic_name_length;

  return mqttsn_encode_packetv(
      MQTTSN_REGISTER, parts, 2u, output, output_capacity, written);
}

mqttsn_status_t mqttsn_encode_publish(
    const mqttsn_publish_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t flags;
  uint8_t packet_id[2];
  uint8_t topic_field[2];
  mqttsn_buffer_t parts[5];
  size_t part_count = 0u;

  if (options == NULL ||
      (options->payload == NULL && options->payload_length != 0u) ||
      options->qos > MQTTSN_QOS_2 ||
      !topic_ref_is_valid(&options->topic, 0)) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  if ((options->qos == MQTTSN_QOS_0 && options->packet_identifier != 0u) ||
      (options->qos != MQTTSN_QOS_0 && options->packet_identifier == 0u) ||
      (options->qos != MQTTSN_QOS_2 && options->duplicate != 0u)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  flags = (uint8_t)options->topic.type;
  if (options->retain) {
    flags |= 0x10u;
  }
  flags |= (uint8_t)((uint8_t)options->qos << 5u);
  if (options->duplicate) {
    flags |= 0x80u;
  }

  parts[part_count++] = (mqttsn_buffer_t){&flags, 1u};

  if (options->qos != MQTTSN_QOS_0) {
    write_u16_packet(packet_id, options->packet_identifier);
    parts[part_count++] = (mqttsn_buffer_t){packet_id, sizeof(packet_id)};
  }

  if (options->topic.type == MQTTSN_TOPIC_NAME) {
    if (options->topic.name_length > 0xFFFFu) {
      return MQTTSN_MALFORMED_PACKET;
    }
    write_u16_packet(topic_field, (uint16_t)options->topic.name_length);
  } else {
    write_u16_packet(topic_field, options->topic.alias);
  }
  parts[part_count++] = (mqttsn_buffer_t){topic_field, sizeof(topic_field)};

  if (options->topic.type == MQTTSN_TOPIC_NAME) {
    parts[part_count++] = (mqttsn_buffer_t){
        options->topic.name, options->topic.name_length};
  }

  parts[part_count++] = (mqttsn_buffer_t){
      options->payload, options->payload_length};

  return mqttsn_encode_packetv(
      MQTTSN_PUBLISH, parts, part_count, output, output_capacity, written);
}

mqttsn_status_t mqttsn_decode_publish(
    const mqttsn_packet_view_t *packet,
    mqttsn_publish_view_t *publish) {
  const uint8_t *body;
  size_t length;
  size_t offset = 0u;
  uint8_t flags;
  uint8_t qos;
  uint8_t topic_type;
  uint16_t topic_value;

  if (packet == NULL || publish == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (packet->type != MQTTSN_PUBLISH) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body = packet->body;
  length = packet->body_length;
  if (length < 3u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(publish, 0, sizeof(*publish));
  flags = body[offset++];
  if ((flags & 0x0Cu) != 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  topic_type = (uint8_t)(flags & 0x03u);
  qos = (uint8_t)((flags >> 5u) & 0x03u);
  if (topic_type == 2u || qos == 3u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  if (qos != MQTTSN_QOS_2 && (flags & 0x80u) != 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  publish->topic.type = (mqttsn_topic_type_t)topic_type;
  publish->qos = (mqttsn_qos_t)qos;
  publish->duplicate = (uint8_t)((flags & 0x80u) != 0u);
  publish->retain = (uint8_t)((flags & 0x10u) != 0u);

  if (publish->qos != MQTTSN_QOS_0) {
    if (length - offset < 2u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    publish->packet_identifier = read_u16_packet(body + offset);
    if (publish->packet_identifier == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    offset += 2u;
  }

  if (length - offset < 2u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  topic_value = read_u16_packet(body + offset);
  offset += 2u;

  if (publish->topic.type == MQTTSN_TOPIC_NAME) {
    size_t topic_length = topic_value;
    if (length - offset < topic_length ||
        !mqttsn_topic_name_is_valid(body + offset, topic_length)) {
      return MQTTSN_MALFORMED_PACKET;
    }
    publish->topic.name = body + offset;
    publish->topic.name_length = topic_length;
    offset += topic_length;
  } else {
    if (topic_value == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    publish->topic.alias = topic_value;
  }

  publish->payload = body + offset;
  publish->payload_length = length - offset;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_encode_subscribe(
    const mqttsn_subscribe_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t flags;
  uint8_t packet_id[2];
  uint8_t alias[2];
  mqttsn_buffer_t parts[3];
  size_t part_count = 0u;

  if (options == NULL ||
      options->packet_identifier == 0u ||
      options->maximum_qos > MQTTSN_QOS_2 ||
      options->retain_handling > 2u ||
      !topic_ref_is_valid(&options->topic, 1)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  flags = (uint8_t)options->topic.type;
  flags |= (uint8_t)((options->retain_handling & 0x03u) << 2u);
  if (options->retain_as_published) {
    flags |= 0x10u;
  }
  flags |= (uint8_t)((uint8_t)options->maximum_qos << 5u);
  if (options->no_local) {
    flags |= 0x80u;
  }

  write_u16_packet(packet_id, options->packet_identifier);
  parts[part_count++] = (mqttsn_buffer_t){&flags, 1u};
  parts[part_count++] = (mqttsn_buffer_t){packet_id, sizeof(packet_id)};

  if (options->topic.type == MQTTSN_TOPIC_NAME) {
    parts[part_count++] = (mqttsn_buffer_t){
        options->topic.name, options->topic.name_length};
  } else {
    write_u16_packet(alias, options->topic.alias);
    parts[part_count++] = (mqttsn_buffer_t){alias, sizeof(alias)};
  }

  return mqttsn_encode_packetv(
      MQTTSN_SUBSCRIBE, parts, part_count, output, output_capacity, written);
}

mqttsn_status_t mqttsn_decode_suback(
    const mqttsn_packet_view_t *packet,
    mqttsn_suback_view_t *suback) {
  const uint8_t *body;
  size_t length;
  size_t offset = 0u;
  uint8_t flags;
  uint8_t topic_type;

  if (packet == NULL || suback == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (packet->type != MQTTSN_SUBACK) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body = packet->body;
  length = packet->body_length;
  if (length < 3u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(suback, 0, sizeof(*suback));
  flags = body[offset++];
  if ((flags & 0xF8u) != 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  topic_type = (uint8_t)(flags & 0x03u);
  if (topic_type != MQTTSN_TOPIC_SESSION_ALIAS &&
      topic_type != MQTTSN_TOPIC_PREDEFINED_ALIAS) {
    return MQTTSN_MALFORMED_PACKET;
  }

  suback->topic_type = (mqttsn_topic_type_t)topic_type;
  suback->has_topic_alias = (uint8_t)((flags & 0x04u) != 0u);
  suback->packet_identifier = read_u16_packet(body + offset);
  if (suback->packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  offset += 2u;

  if (suback->has_topic_alias) {
    if (length - offset < 2u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    suback->topic_alias = read_u16_packet(body + offset);
    if (suback->topic_alias == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    offset += 2u;
  }

  if (length - offset > 1u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  if (length - offset == 1u) {
    suback->has_reason_code = 1u;
    suback->reason_code = body[offset];
  }

  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_encode_unsubscribe(
    const mqttsn_unsubscribe_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t flags;
  uint8_t packet_id[2];
  uint8_t alias[2];
  mqttsn_buffer_t parts[3];

  if (options == NULL ||
      options->packet_identifier == 0u ||
      !topic_ref_is_valid(&options->topic, 1)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  flags = (uint8_t)options->topic.type;
  write_u16_packet(packet_id, options->packet_identifier);
  parts[0] = (mqttsn_buffer_t){&flags, 1u};
  parts[1] = (mqttsn_buffer_t){packet_id, sizeof(packet_id)};

  if (options->topic.type == MQTTSN_TOPIC_NAME) {
    parts[2] = (mqttsn_buffer_t){
        options->topic.name, options->topic.name_length};
  } else {
    write_u16_packet(alias, options->topic.alias);
    parts[2] = (mqttsn_buffer_t){alias, sizeof(alias)};
  }

  return mqttsn_encode_packetv(
      MQTTSN_UNSUBSCRIBE, parts, 3u, output, output_capacity, written);
}

mqttsn_status_t mqttsn_encode_ack(
    mqttsn_packet_type_t type,
    uint16_t packet_identifier,
    uint8_t has_reason_code,
    uint8_t reason_code,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t body[3];
  size_t body_length = 2u;

  if (!ack_type_is_valid(type) || packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  write_u16_packet(body, packet_identifier);
  if (has_reason_code) {
    body[2] = reason_code;
    body_length = 3u;
  }

  return mqttsn_encode_packet(
      type, body, body_length, output, output_capacity, written);
}

mqttsn_status_t mqttsn_decode_ack(
    const mqttsn_packet_view_t *packet,
    mqttsn_ack_view_t *ack) {
  if (packet == NULL || ack == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (!ack_type_is_valid(packet->type) ||
      (packet->body_length != 2u && packet->body_length != 3u)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(ack, 0, sizeof(*ack));
  ack->packet_identifier = read_u16_packet(packet->body);
  if (ack->packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if (packet->body_length == 3u) {
    ack->has_reason_code = 1u;
    ack->reason_code = packet->body[2];
  }
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_encode_pingreq(
    uint16_t packet_identifier,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t body[2];

  if (packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  write_u16_packet(body, packet_identifier);
  return mqttsn_encode_packet(
      MQTTSN_PINGREQ, body, sizeof(body), output, output_capacity, written);
}

mqttsn_status_t mqttsn_decode_pingresp(
    const mqttsn_packet_view_t *packet,
    mqttsn_pingresp_view_t *pingresp) {
  if (packet == NULL || pingresp == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (packet->type != MQTTSN_PINGRESP ||
      (packet->body_length != 2u && packet->body_length != 3u)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(pingresp, 0, sizeof(*pingresp));
  pingresp->packet_identifier = read_u16_packet(packet->body);
  if (pingresp->packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  if (packet->body_length == 3u) {
    pingresp->has_application_messages_remaining = 1u;
    pingresp->application_messages_remaining = packet->body[2];
  }
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_encode_sleepreq(
    const mqttsn_sleepreq_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t body[7];

  if (options == NULL ||
      options->packet_identifier == 0u ||
      options->sleep_duration == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body[0] = options->retain_topic_aliases ? 0x01u : 0x00u;
  write_u16_packet(body + 1u, options->packet_identifier);
  write_u32_packet(body + 3u, options->sleep_duration);

  return mqttsn_encode_packet(
      MQTTSN_SLEEPREQ, body, sizeof(body), output, output_capacity, written);
}

mqttsn_status_t mqttsn_decode_sleepresp(
    const mqttsn_packet_view_t *packet,
    mqttsn_sleepresp_view_t *sleepresp) {
  const uint8_t *body;
  size_t length;
  size_t offset = 0u;
  uint8_t flags;

  if (packet == NULL || sleepresp == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (packet->type != MQTTSN_SLEEPRESP || packet->body_length < 3u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  body = packet->body;
  length = packet->body_length;
  memset(sleepresp, 0, sizeof(*sleepresp));

  flags = body[offset++];
  if ((flags & 0xFEu) != 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  sleepresp->packet_identifier = read_u16_packet(body + offset);
  if (sleepresp->packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  offset += 2u;

  if ((flags & 0x01u) != 0u) {
    if (length - offset < 4u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    sleepresp->has_sleep_duration = 1u;
    sleepresp->sleep_duration = read_u32_packet(body + offset);
    if (sleepresp->sleep_duration == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    offset += 4u;
  }

  if (length - offset > 1u) {
    return MQTTSN_MALFORMED_PACKET;
  }
  if (length - offset == 1u) {
    sleepresp->has_reason_code = 1u;
    sleepresp->reason_code = body[offset];
  }

  return MQTTSN_OK;
}



mqttsn_status_t mqttsn_encode_auth(
    const mqttsn_auth_t *auth,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t prefix[4];
  mqttsn_buffer_t parts[3];

  if (auth == NULL || output == NULL || written == NULL ||
      auth->packet_identifier == 0u ||
      auth->authentication_method_length > 0xFFu ||
      (auth->authentication_method == NULL && auth->authentication_method_length != 0u) ||
      (auth->authentication_data == NULL && auth->authentication_data_length != 0u) ||
      !mqttsn_utf8_is_valid(auth->authentication_method, auth->authentication_method_length)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  write_u16_packet(prefix, auth->packet_identifier);
  prefix[2] = auth->reason_code;
  prefix[3] = (uint8_t)auth->authentication_method_length;

  parts[0] = (mqttsn_buffer_t){prefix, sizeof(prefix)};
  parts[1] = (mqttsn_buffer_t){
      auth->authentication_method, auth->authentication_method_length};
  parts[2] = (mqttsn_buffer_t){
      auth->authentication_data, auth->authentication_data_length};

  return mqttsn_encode_packetv(
      MQTTSN_AUTH, parts, 3u, output, output_capacity, written);
}

mqttsn_status_t mqttsn_decode_auth(
    const mqttsn_packet_view_t *packet,
    mqttsn_auth_t *auth) {
  const uint8_t *body;
  size_t method_length;

  if (packet == NULL || auth == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (packet->type != MQTTSN_AUTH || packet->body_length < 4u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(auth, 0, sizeof(*auth));
  body = packet->body;
  auth->packet_identifier = read_u16_packet(body);
  if (auth->packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  auth->reason_code = body[2];
  method_length = body[3];
  if (packet->body_length < 4u + method_length) {
    return MQTTSN_MALFORMED_PACKET;
  }

  auth->authentication_method = body + 4u;
  auth->authentication_method_length = method_length;
  if (!mqttsn_utf8_is_valid(
          auth->authentication_method,
          auth->authentication_method_length)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  auth->authentication_data = body + 4u + method_length;
  auth->authentication_data_length =
      packet->body_length - 4u - method_length;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_encode_disconnect(
    const mqttsn_disconnect_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  uint8_t fixed[8];
  size_t fixed_length = 1u;
  uint8_t flags = 0u;
  mqttsn_buffer_t parts[2];
  size_t part_count = 1u;

  if (options == NULL || output == NULL || written == NULL ||
      (options->reason_string == NULL && options->reason_string_length != 0u)) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  if (options->has_packet_identifier) {
    if (options->packet_identifier == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    flags |= 0x01u;
  }
  if (options->has_session_expiry_interval) {
    flags |= 0x02u;
  }
  if (options->has_reason_code) {
    flags |= 0x04u;
  }
  if (!mqttsn_utf8_is_valid(options->reason_string, options->reason_string_length)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  fixed[0] = flags;
  if (options->has_packet_identifier) {
    write_u16_packet(fixed + fixed_length, options->packet_identifier);
    fixed_length += 2u;
  }
  if (options->has_reason_code) {
    fixed[fixed_length++] = options->reason_code;
  }
  if (options->has_session_expiry_interval) {
    write_u32_packet(fixed + fixed_length, options->session_expiry_interval);
    fixed_length += 4u;
  }

  parts[0] = (mqttsn_buffer_t){fixed, fixed_length};
  if (options->reason_string_length != 0u) {
    parts[1] = (mqttsn_buffer_t){
        options->reason_string, options->reason_string_length};
    part_count = 2u;
  }

  return mqttsn_encode_packetv(
      MQTTSN_DISCONNECT, parts, part_count, output, output_capacity, written);
}

mqttsn_status_t mqttsn_decode_disconnect(
    const mqttsn_packet_view_t *packet,
    mqttsn_disconnect_view_t *disconnect) {
  const uint8_t *body;
  size_t length;
  size_t offset = 0u;
  uint8_t flags;

  if (packet == NULL || disconnect == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }
  if (packet->type != MQTTSN_DISCONNECT || packet->body_length < 1u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  memset(disconnect, 0, sizeof(*disconnect));
  body = packet->body;
  length = packet->body_length;
  flags = body[offset++];

  if ((flags & 0xF8u) != 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if ((flags & 0x01u) != 0u) {
    if (length - offset < 2u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    disconnect->has_packet_identifier = 1u;
    disconnect->packet_identifier = read_u16_packet(body + offset);
    if (disconnect->packet_identifier == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    offset += 2u;
  }

  if ((flags & 0x04u) != 0u) {
    if (length - offset < 1u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    disconnect->has_reason_code = 1u;
    disconnect->reason_code = body[offset++];
  }

  if ((flags & 0x02u) != 0u) {
    if (length - offset < 4u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    disconnect->has_session_expiry_interval = 1u;
    disconnect->session_expiry_interval = read_u32_packet(body + offset);
    offset += 4u;
  }

  disconnect->reason_string = body + offset;
  disconnect->reason_string_length = length - offset;
  if (!mqttsn_utf8_is_valid(
          disconnect->reason_string, disconnect->reason_string_length)) {
    return MQTTSN_MALFORMED_PACKET;
  }

  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_encode_wakeup(
    uint8_t *output,
    size_t output_capacity,
    size_t *written) {
  return mqttsn_encode_packet(
      MQTTSN_WAKEUP, NULL, 0u, output, output_capacity, written);
}
