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

#include "mqttsn/client.h"

#include "mqttsn/packets.h"

#include <string.h>

static uint16_t read_u16_client(const uint8_t *data) {
  return (uint16_t)(((uint16_t)data[0] << 8u) | (uint16_t)data[1]);
}

static void clear_outbound(mqttsn_client_t *client) {
  client->has_outbound_request = 0u;
  client->outbound_request_type = (mqttsn_packet_type_t)0;
  client->expected_response_type = (mqttsn_packet_type_t)0;
  client->outbound_packet_identifier = 0u;
  client->qos2_pubrel_pending = 0u;
}

static void clear_inbound(mqttsn_client_t *client) {
  client->has_inbound_request = 0u;
  client->inbound_request_type = (mqttsn_packet_type_t)0;
  client->inbound_packet_identifier = 0u;
}

static void reset_connection_flow(mqttsn_client_t *client) {
  clear_outbound(client);
  clear_inbound(client);
}

void mqttsn_client_init(
    mqttsn_client_t *client,
    uint16_t initial_packet_identifier) {
  if (client == NULL) {
    return;
  }
  memset(client, 0, sizeof(*client));
  client->state = MQTTSN_CLIENT_NONE;
  client->next_packet_identifier =
      initial_packet_identifier == 0u ? 1u : initial_packet_identifier;
}

uint16_t mqttsn_client_next_packet_identifier(mqttsn_client_t *client) {
  uint16_t result;

  if (client == NULL) {
    return 0u;
  }

  result = client->next_packet_identifier;
  if (result == 0u) {
    result = 1u;
  }

  client->next_packet_identifier =
      result == 0xFFFFu ? 1u : (uint16_t)(result + 1u);

  if (client->has_outbound_request &&
      client->next_packet_identifier == client->outbound_packet_identifier) {
    client->next_packet_identifier =
        client->next_packet_identifier == 0xFFFFu
            ? 1u
            : (uint16_t)(client->next_packet_identifier + 1u);
  }

  return result;
}

static int is_client_response_type(mqttsn_packet_type_t type) {
  return type == MQTTSN_PUBACK ||
         type == MQTTSN_PUBREC ||
         type == MQTTSN_PUBCOMP ||
         type == MQTTSN_REGACK;
}

static int allowed_without_virtual_connection(mqttsn_packet_type_t type) {
  return type == MQTTSN_CONNECT ||
         type == MQTTSN_PUBWOS ||
         type == MQTTSN_SEARCHGW ||
         type == MQTTSN_GWINFO;
}

int mqttsn_client_can_send(
    const mqttsn_client_t *client,
    mqttsn_packet_type_t type) {
  if (client == NULL) {
    return 0;
  }

  switch (client->state) {
    case MQTTSN_CLIENT_NONE:
    case MQTTSN_CLIENT_DISCONNECTED:
      return allowed_without_virtual_connection(type);

    case MQTTSN_CLIENT_CONNECTING:
      return type == MQTTSN_AUTH ||
             type == MQTTSN_DISCONNECT ||
             type == MQTTSN_PUBWOS ||
             type == MQTTSN_SEARCHGW ||
             type == MQTTSN_GWINFO;

    case MQTTSN_CLIENT_ASLEEP:
      return type == MQTTSN_PINGREQ ||
             type == MQTTSN_CONNECT ||
             type == MQTTSN_DISCONNECT;

    case MQTTSN_CLIENT_AWAKE:
      return is_client_response_type(type) ||
             type == MQTTSN_CONNECT ||
             type == MQTTSN_DISCONNECT;

    case MQTTSN_CLIENT_ACTIVE:
      return type != MQTTSN_CONNACK &&
             type != MQTTSN_SUBACK &&
             type != MQTTSN_UNSUBACK &&
             type != MQTTSN_PINGRESP &&
             type != MQTTSN_SLEEPRESP &&
             type != MQTTSN_ADVERTISE &&
             type != MQTTSN_WAKEUP;

    default:
      return 0;
  }
}

static mqttsn_status_t decode_single(
    const uint8_t *data,
    size_t length,
    mqttsn_packet_view_t *packet) {
  size_t consumed = 0u;
  mqttsn_status_t status;

  if (data == NULL || packet == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  status = mqttsn_decode_packet(data, length, packet, &consumed);
  if (status != MQTTSN_OK) {
    return status;
  }
  if (consumed != length) {
    return MQTTSN_MALFORMED_PACKET;
  }
  return MQTTSN_OK;
}

static mqttsn_status_t outbound_request_info(
    const mqttsn_packet_view_t *packet,
    uint8_t *is_request,
    uint16_t *packet_identifier,
    mqttsn_packet_type_t *expected_response,
    uint8_t *is_qos2_publish) {
  const uint8_t *body = packet->body;

  *is_request = 0u;
  *packet_identifier = 0u;
  *expected_response = (mqttsn_packet_type_t)0;
  *is_qos2_publish = 0u;

  switch (packet->type) {
    case MQTTSN_PUBLISH: {
      mqttsn_publish_view_t publish;
      mqttsn_status_t status = mqttsn_decode_publish(packet, &publish);
      if (status != MQTTSN_OK) {
        return status;
      }
      if (publish.qos == MQTTSN_QOS_0) {
        return MQTTSN_OK;
      }
      *is_request = 1u;
      *packet_identifier = publish.packet_identifier;
      *expected_response =
          publish.qos == MQTTSN_QOS_1 ? MQTTSN_PUBACK : MQTTSN_PUBREC;
      *is_qos2_publish = (uint8_t)(publish.qos == MQTTSN_QOS_2);
      return MQTTSN_OK;
    }

    case MQTTSN_PUBREL:
      if (packet->body_length < 2u) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *is_request = 1u;
      *packet_identifier = read_u16_client(body);
      *expected_response = MQTTSN_PUBCOMP;
      return *packet_identifier == 0u ? MQTTSN_MALFORMED_PACKET : MQTTSN_OK;

    case MQTTSN_REGISTER:
    case MQTTSN_SUBSCRIBE:
    case MQTTSN_UNSUBSCRIBE:
    case MQTTSN_SLEEPREQ:
      if (packet->body_length < 3u) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *is_request = 1u;
      *packet_identifier = read_u16_client(body + 1u);
      *expected_response =
          packet->type == MQTTSN_REGISTER ? MQTTSN_REGACK :
          packet->type == MQTTSN_SUBSCRIBE ? MQTTSN_SUBACK :
          packet->type == MQTTSN_UNSUBSCRIBE ? MQTTSN_UNSUBACK :
          MQTTSN_SLEEPRESP;
      return *packet_identifier == 0u ? MQTTSN_MALFORMED_PACKET : MQTTSN_OK;

    case MQTTSN_PINGREQ:
    case MQTTSN_AUTH:
      if (packet->body_length < 2u) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *is_request = 1u;
      *packet_identifier = read_u16_client(body);
      *expected_response =
          packet->type == MQTTSN_PINGREQ ? MQTTSN_PINGRESP : MQTTSN_AUTH;
      return *packet_identifier == 0u ? MQTTSN_MALFORMED_PACKET : MQTTSN_OK;

    default:
      return MQTTSN_OK;
  }
}

static mqttsn_status_t track_client_response(
    mqttsn_client_t *client,
    const mqttsn_packet_view_t *packet) {
  mqttsn_ack_view_t ack;

  if (!client->has_inbound_request) {
    return MQTTSN_OK;
  }

  switch (packet->type) {
    case MQTTSN_PUBACK:
      if (client->inbound_request_type != MQTTSN_PUBLISH ||
          mqttsn_decode_ack(packet, &ack) != MQTTSN_OK ||
          ack.packet_identifier != client->inbound_packet_identifier) {
        return MQTTSN_STATE_ERROR;
      }
      clear_inbound(client);
      break;

    case MQTTSN_PUBREC:
      if (client->inbound_request_type != MQTTSN_PUBLISH ||
          mqttsn_decode_ack(packet, &ack) != MQTTSN_OK ||
          ack.packet_identifier != client->inbound_packet_identifier) {
        return MQTTSN_STATE_ERROR;
      }
      client->inbound_request_type = MQTTSN_PUBREL;
      break;

    case MQTTSN_PUBCOMP:
      if (client->inbound_request_type != MQTTSN_PUBREL ||
          mqttsn_decode_ack(packet, &ack) != MQTTSN_OK ||
          ack.packet_identifier != client->inbound_packet_identifier) {
        return MQTTSN_STATE_ERROR;
      }
      clear_inbound(client);
      break;

    case MQTTSN_REGACK:
      if (client->inbound_request_type != MQTTSN_REGISTER ||
          packet->body_length < 3u ||
          read_u16_client(packet->body + 1u) !=
              client->inbound_packet_identifier) {
        return MQTTSN_STATE_ERROR;
      }
      clear_inbound(client);
      break;

    default:
      break;
  }

  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_client_track_outbound(
    mqttsn_client_t *client,
    const uint8_t *packet_data,
    size_t packet_length) {
  mqttsn_packet_view_t packet;
  mqttsn_status_t status;
  uint8_t is_request;
  uint8_t is_qos2_publish;
  uint16_t packet_identifier;
  mqttsn_packet_type_t expected_response;

  if (client == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  status = decode_single(packet_data, packet_length, &packet);
  if (status != MQTTSN_OK) {
    return status;
  }
  if (!mqttsn_client_can_send(client, packet.type)) {
    return MQTTSN_STATE_ERROR;
  }

  status = track_client_response(client, &packet);
  if (status != MQTTSN_OK) {
    return status;
  }

  if (packet.type == MQTTSN_CONNECT) {
    if (packet.body_length < 3u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    client->connect_packet_identifier = read_u16_client(packet.body + 1u);
    if (client->connect_packet_identifier == 0u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    reset_connection_flow(client);
    client->state = MQTTSN_CLIENT_CONNECTING;
    return MQTTSN_OK;
  }

  if (packet.type == MQTTSN_DISCONNECT) {
    reset_connection_flow(client);
    client->state = MQTTSN_CLIENT_DISCONNECTED;
    return MQTTSN_OK;
  }

  status = outbound_request_info(
      &packet,
      &is_request,
      &packet_identifier,
      &expected_response,
      &is_qos2_publish);
  if (status != MQTTSN_OK || !is_request) {
    return status;
  }

  if (client->has_outbound_request) {
    if (packet.type == MQTTSN_PUBREL &&
        client->outbound_request_type == MQTTSN_PUBLISH &&
        client->qos2_pubrel_pending &&
        packet_identifier == client->outbound_packet_identifier) {
      client->outbound_request_type = MQTTSN_PUBREL;
      client->expected_response_type = MQTTSN_PUBCOMP;
      client->qos2_pubrel_pending = 0u;
      return MQTTSN_OK;
    }

    if (packet.type == MQTTSN_AUTH) {
      return MQTTSN_FLOW_CONTROL;
    }

    if (packet.type != client->outbound_request_type ||
        packet_identifier != client->outbound_packet_identifier) {
      return MQTTSN_FLOW_CONTROL;
    }
    return MQTTSN_OK;
  }

  client->has_outbound_request = 1u;
  client->outbound_request_type = packet.type;
  client->expected_response_type = expected_response;
  client->outbound_packet_identifier = packet_identifier;
  client->qos2_pubrel_pending = 0u;
  if (packet.type == MQTTSN_AUTH) {
    client->connect_packet_identifier = packet_identifier;
  }

  if (packet.type == MQTTSN_PINGREQ &&
      client->state == MQTTSN_CLIENT_ASLEEP) {
    client->state = MQTTSN_CLIENT_AWAKE;
  }

  (void)is_qos2_publish;
  return MQTTSN_OK;
}

static mqttsn_status_t response_packet_identifier(
    const mqttsn_packet_view_t *packet,
    uint16_t *packet_identifier) {
  mqttsn_ack_view_t ack;

  switch (packet->type) {
    case MQTTSN_PUBACK:
    case MQTTSN_PUBREC:
    case MQTTSN_PUBCOMP:
    case MQTTSN_UNSUBACK:
      if (mqttsn_decode_ack(packet, &ack) != MQTTSN_OK) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *packet_identifier = ack.packet_identifier;
      return MQTTSN_OK;

    case MQTTSN_SUBACK: {
      mqttsn_suback_view_t suback;
      if (mqttsn_decode_suback(packet, &suback) != MQTTSN_OK) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *packet_identifier = suback.packet_identifier;
      return MQTTSN_OK;
    }

    case MQTTSN_PINGRESP: {
      mqttsn_pingresp_view_t pingresp;
      if (mqttsn_decode_pingresp(packet, &pingresp) != MQTTSN_OK) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *packet_identifier = pingresp.packet_identifier;
      return MQTTSN_OK;
    }

    case MQTTSN_SLEEPRESP: {
      mqttsn_sleepresp_view_t sleepresp;
      if (mqttsn_decode_sleepresp(packet, &sleepresp) != MQTTSN_OK) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *packet_identifier = sleepresp.packet_identifier;
      return MQTTSN_OK;
    }

    case MQTTSN_REGACK:
      if (packet->body_length < 3u) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *packet_identifier = read_u16_client(packet->body + 1u);
      return *packet_identifier == 0u ? MQTTSN_MALFORMED_PACKET : MQTTSN_OK;

    case MQTTSN_AUTH:
      if (packet->body_length < 2u) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *packet_identifier = read_u16_client(packet->body);
      return *packet_identifier == 0u ? MQTTSN_MALFORMED_PACKET : MQTTSN_OK;

    default:
      return MQTTSN_STATE_ERROR;
  }
}

static mqttsn_status_t track_inbound_request(
    mqttsn_client_t *client,
    const mqttsn_packet_view_t *packet) {
  uint16_t packet_identifier = 0u;
  uint8_t is_request = 0u;

  if (packet->type == MQTTSN_PUBLISH) {
    mqttsn_publish_view_t publish;
    mqttsn_status_t status = mqttsn_decode_publish(packet, &publish);
    if (status != MQTTSN_OK) {
      return status;
    }
    if (publish.qos == MQTTSN_QOS_0) {
      return MQTTSN_OK;
    }
    is_request = 1u;
    packet_identifier = publish.packet_identifier;
  } else if (packet->type == MQTTSN_REGISTER) {
    if (packet->body_length < 3u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    is_request = 1u;
    packet_identifier = read_u16_client(packet->body + 1u);
  } else if (packet->type == MQTTSN_PUBREL) {
    if (packet->body_length < 2u) {
      return MQTTSN_MALFORMED_PACKET;
    }
    packet_identifier = read_u16_client(packet->body);
    if (!client->has_inbound_request ||
        client->inbound_request_type != MQTTSN_PUBREL ||
        packet_identifier != client->inbound_packet_identifier) {
      return MQTTSN_STATE_ERROR;
    }
    return MQTTSN_OK;
  }

  if (!is_request) {
    return MQTTSN_OK;
  }
  if (packet_identifier == 0u) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if (client->has_inbound_request) {
    if (client->inbound_request_type == packet->type &&
        client->inbound_packet_identifier == packet_identifier) {
      return MQTTSN_OK;
    }
    return MQTTSN_FLOW_CONTROL;
  }

  client->has_inbound_request = 1u;
  client->inbound_request_type = packet->type;
  client->inbound_packet_identifier = packet_identifier;
  return MQTTSN_OK;
}

mqttsn_status_t mqttsn_client_track_inbound(
    mqttsn_client_t *client,
    const uint8_t *packet_data,
    size_t packet_length) {
  mqttsn_packet_view_t packet;
  mqttsn_status_t status;

  if (client == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  status = decode_single(packet_data, packet_length, &packet);
  if (status != MQTTSN_OK) {
    return status;
  }

  if (packet.type == MQTTSN_CONNACK) {
    mqttsn_connack_view_t connack;
    if (client->state != MQTTSN_CLIENT_CONNECTING) {
      return MQTTSN_STATE_ERROR;
    }
    status = mqttsn_decode_connack(&packet, &connack);
    if (status != MQTTSN_OK) {
      return status;
    }
    if (connack.packet_identifier != client->connect_packet_identifier) {
      return MQTTSN_STATE_ERROR;
    }
    clear_outbound(client);
    client->state =
        connack.reason_code == 0u
            ? MQTTSN_CLIENT_ACTIVE
            : MQTTSN_CLIENT_DISCONNECTED;
    return MQTTSN_OK;
  }

  if (packet.type == MQTTSN_DISCONNECT) {
    reset_connection_flow(client);
    client->state = MQTTSN_CLIENT_DISCONNECTED;
    return MQTTSN_OK;
  }

  if (client->has_outbound_request &&
      packet.type == client->expected_response_type) {
    uint16_t packet_identifier;
    status = response_packet_identifier(&packet, &packet_identifier);
    if (status != MQTTSN_OK) {
      return status;
    }
    if (packet_identifier != client->outbound_packet_identifier) {
      return MQTTSN_STATE_ERROR;
    }

    if (packet.type == MQTTSN_PUBREC &&
        client->outbound_request_type == MQTTSN_PUBLISH) {
      client->qos2_pubrel_pending = 1u;
      return MQTTSN_OK;
    }

    if (packet.type == MQTTSN_SLEEPRESP) {
      mqttsn_sleepresp_view_t sleepresp;
      status = mqttsn_decode_sleepresp(&packet, &sleepresp);
      if (status != MQTTSN_OK) {
        return status;
      }
      if (!sleepresp.has_reason_code || sleepresp.reason_code < 0x80u) {
        client->state = MQTTSN_CLIENT_ASLEEP;
      }
    } else if (packet.type == MQTTSN_PINGRESP &&
               client->state == MQTTSN_CLIENT_AWAKE) {
      client->state = MQTTSN_CLIENT_ASLEEP;
    }

    clear_outbound(client);
    return MQTTSN_OK;
  }

  status = track_inbound_request(client, &packet);
  if (status != MQTTSN_OK) {
    return status;
  }

  return MQTTSN_OK;
}


void mqttsn_retry_timer_init(
    mqttsn_retry_timer_t *timer,
    uint64_t retry_interval_ms,
    uint32_t maximum_retry_count) {
  if (timer == NULL) {
    return;
  }
  memset(timer, 0, sizeof(*timer));
  timer->retry_interval_ms = retry_interval_ms;
  timer->maximum_retry_count = maximum_retry_count;
}

void mqttsn_retry_timer_start(
    mqttsn_retry_timer_t *timer,
    uint64_t now_ms) {
  if (timer == NULL || timer->retry_interval_ms == 0u) {
    return;
  }
  timer->active = 1u;
  timer->retries_sent = 0u;
  timer->deadline_ms = now_ms + timer->retry_interval_ms;
}

void mqttsn_retry_timer_cancel(
    mqttsn_retry_timer_t *timer) {
  if (timer == NULL) {
    return;
  }
  timer->active = 0u;
  timer->retries_sent = 0u;
}

mqttsn_retry_action_t mqttsn_retry_timer_poll(
    mqttsn_retry_timer_t *timer,
    uint64_t now_ms) {
  if (timer == NULL || !timer->active || now_ms < timer->deadline_ms) {
    return MQTTSN_RETRY_NONE;
  }

  if (timer->retries_sent < timer->maximum_retry_count) {
    timer->retries_sent++;
    timer->deadline_ms = now_ms + timer->retry_interval_ms;
    return MQTTSN_RETRY_RETRANSMIT;
  }

  timer->active = 0u;
  return MQTTSN_RETRY_DELETE_CONNECTION;
}

void mqttsn_keep_alive_timer_init(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t keep_alive_ms) {
  if (timer == NULL) {
    return;
  }
  memset(timer, 0, sizeof(*timer));
  timer->keep_alive_ms = keep_alive_ms;
}

void mqttsn_keep_alive_timer_start(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t now_ms) {
  if (timer == NULL || timer->keep_alive_ms == 0u) {
    return;
  }
  timer->active = 1u;
  timer->deadline_ms = now_ms + timer->keep_alive_ms;
}

void mqttsn_keep_alive_timer_outbound_activity(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t now_ms) {
  if (timer == NULL || !timer->active) {
    return;
  }
  timer->deadline_ms = now_ms + timer->keep_alive_ms;
}

void mqttsn_keep_alive_timer_stop(
    mqttsn_keep_alive_timer_t *timer) {
  if (timer == NULL) {
    return;
  }
  timer->active = 0u;
}

mqttsn_keep_alive_action_t mqttsn_keep_alive_timer_poll(
    mqttsn_keep_alive_timer_t *timer,
    uint64_t now_ms) {
  if (timer == NULL || !timer->active || now_ms < timer->deadline_ms) {
    return MQTTSN_KEEP_ALIVE_NONE;
  }
  timer->deadline_ms = now_ms + timer->keep_alive_ms;
  return MQTTSN_KEEP_ALIVE_SEND_PINGREQ;
}

void mqttsn_client_retry_exhausted(mqttsn_client_t *client) {
  if (client == NULL) {
    return;
  }
  reset_connection_flow(client);
  client->state = MQTTSN_CLIENT_DISCONNECTED;
}
