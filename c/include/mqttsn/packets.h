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

#ifndef MQTT_SN_2_PACKETS_H
#define MQTT_SN_2_PACKETS_H

#include "mqttsn/mqttsn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MQTTSN_TOPIC_SESSION_ALIAS = 0,
  MQTTSN_TOPIC_PREDEFINED_ALIAS = 1,
  MQTTSN_TOPIC_NAME = 3
} mqttsn_topic_type_t;

typedef enum {
  MQTTSN_QOS_0 = 0,
  MQTTSN_QOS_1 = 1,
  MQTTSN_QOS_2 = 2
} mqttsn_qos_t;

typedef struct {
  mqttsn_topic_type_t type;
  uint16_t alias;
  const uint8_t *name;
  size_t name_length;
} mqttsn_topic_ref_t;

typedef struct {
  mqttsn_qos_t qos;
  uint8_t duplicate;
  uint8_t retain;
  uint16_t packet_identifier;
  mqttsn_topic_ref_t topic;
  const uint8_t *payload;
  size_t payload_length;
} mqttsn_publish_options_t;

typedef struct {
  mqttsn_qos_t qos;
  uint8_t duplicate;
  uint8_t retain;
  uint16_t packet_identifier;
  mqttsn_topic_ref_t topic;
  const uint8_t *payload;
  size_t payload_length;
} mqttsn_publish_view_t;

typedef struct {
  uint16_t packet_identifier;
  mqttsn_topic_ref_t topic;
  uint8_t retain_handling;
  uint8_t retain_as_published;
  mqttsn_qos_t maximum_qos;
  uint8_t no_local;
} mqttsn_subscribe_options_t;

typedef struct {
  mqttsn_topic_type_t topic_type;
  uint8_t has_topic_alias;
  uint16_t packet_identifier;
  uint16_t topic_alias;
  uint8_t reason_code;
  uint8_t has_reason_code;
} mqttsn_suback_view_t;

typedef struct {
  uint16_t packet_identifier;
  mqttsn_topic_ref_t topic;
} mqttsn_unsubscribe_options_t;



typedef struct {
  const uint8_t *client_identifier;
  size_t client_identifier_length;
  const uint8_t *mqttsn_packet;
  size_t mqttsn_packet_length;
} mqttsn_connection_encapsulation_t;

typedef struct {
  const uint8_t *client_addressing_information;
  size_t client_addressing_information_length;
  const uint8_t *mqttsn_packet;
  size_t mqttsn_packet_length;
} mqttsn_forwarder_encapsulation_t;

mqttsn_status_t mqttsn_encode_connection_encapsulation(
    const mqttsn_connection_encapsulation_t *encapsulation,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_connection_encapsulation(
    const mqttsn_packet_view_t *packet,
    mqttsn_connection_encapsulation_t *encapsulation);

mqttsn_status_t mqttsn_encode_forwarder_encapsulation(
    const mqttsn_forwarder_encapsulation_t *encapsulation,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_forwarder_encapsulation(
    const mqttsn_packet_view_t *packet,
    mqttsn_forwarder_encapsulation_t *encapsulation);

typedef struct {
  uint8_t retain;
  mqttsn_topic_ref_t topic;
  const uint8_t *payload;
  size_t payload_length;
} mqttsn_pubwos_t;

typedef struct {
  uint8_t gateway_identifier;
  uint16_t duration;
} mqttsn_advertise_t;

typedef struct {
  const uint8_t *additional_network_information;
  size_t additional_network_information_length;
} mqttsn_searchgw_t;

typedef struct {
  uint8_t gateway_identifier;
  const uint8_t *gateway_address;
  size_t gateway_address_length;
} mqttsn_gwinfo_t;

mqttsn_status_t mqttsn_encode_pubwos(
    const mqttsn_pubwos_t *packet,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_pubwos(
    const mqttsn_packet_view_t *packet,
    mqttsn_pubwos_t *pubwos);

mqttsn_status_t mqttsn_encode_advertise(
    const mqttsn_advertise_t *packet,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_advertise(
    const mqttsn_packet_view_t *packet,
    mqttsn_advertise_t *advertise);

mqttsn_status_t mqttsn_encode_searchgw(
    const mqttsn_searchgw_t *packet,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_searchgw(
    const mqttsn_packet_view_t *packet,
    mqttsn_searchgw_t *searchgw);

mqttsn_status_t mqttsn_encode_gwinfo(
    const mqttsn_gwinfo_t *packet,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_gwinfo(
    const mqttsn_packet_view_t *packet,
    mqttsn_gwinfo_t *gwinfo);

typedef struct {
  uint16_t packet_identifier;
  uint8_t reason_code;
  uint8_t has_reason_code;
} mqttsn_ack_view_t;

typedef struct {
  uint16_t packet_identifier;
  uint8_t has_application_messages_remaining;
  uint8_t application_messages_remaining;
} mqttsn_pingresp_view_t;

typedef struct {
  uint16_t packet_identifier;
  uint8_t retain_topic_aliases;
  uint32_t sleep_duration;
} mqttsn_sleepreq_options_t;

typedef struct {
  uint16_t packet_identifier;
  uint8_t has_sleep_duration;
  uint32_t sleep_duration;
  uint8_t has_reason_code;
  uint8_t reason_code;
} mqttsn_sleepresp_view_t;

mqttsn_status_t mqttsn_encode_register(
    uint16_t packet_identifier,
    const uint8_t *topic_name,
    size_t topic_name_length,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_encode_publish(
    const mqttsn_publish_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_publish(
    const mqttsn_packet_view_t *packet,
    mqttsn_publish_view_t *publish);

mqttsn_status_t mqttsn_encode_subscribe(
    const mqttsn_subscribe_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_suback(
    const mqttsn_packet_view_t *packet,
    mqttsn_suback_view_t *suback);

mqttsn_status_t mqttsn_encode_unsubscribe(
    const mqttsn_unsubscribe_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_encode_ack(
    mqttsn_packet_type_t type,
    uint16_t packet_identifier,
    uint8_t has_reason_code,
    uint8_t reason_code,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_ack(
    const mqttsn_packet_view_t *packet,
    mqttsn_ack_view_t *ack);

mqttsn_status_t mqttsn_encode_pingreq(
    uint16_t packet_identifier,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_pingresp(
    const mqttsn_packet_view_t *packet,
    mqttsn_pingresp_view_t *pingresp);

mqttsn_status_t mqttsn_encode_sleepreq(
    const mqttsn_sleepreq_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_sleepresp(
    const mqttsn_packet_view_t *packet,
    mqttsn_sleepresp_view_t *sleepresp);



typedef struct {
  uint16_t packet_identifier;
  uint8_t reason_code;
  const uint8_t *authentication_method;
  size_t authentication_method_length;
  const uint8_t *authentication_data;
  size_t authentication_data_length;
} mqttsn_auth_t;

mqttsn_status_t mqttsn_encode_auth(
    const mqttsn_auth_t *auth,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_auth(
    const mqttsn_packet_view_t *packet,
    mqttsn_auth_t *auth);

typedef struct {
  uint8_t has_packet_identifier;
  uint16_t packet_identifier;
  uint8_t has_reason_code;
  uint8_t reason_code;
  uint8_t has_session_expiry_interval;
  uint32_t session_expiry_interval;
  const uint8_t *reason_string;
  size_t reason_string_length;
} mqttsn_disconnect_options_t;

typedef mqttsn_disconnect_options_t mqttsn_disconnect_view_t;

mqttsn_status_t mqttsn_encode_disconnect(
    const mqttsn_disconnect_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_disconnect(
    const mqttsn_packet_view_t *packet,
    mqttsn_disconnect_view_t *disconnect);

mqttsn_status_t mqttsn_encode_wakeup(
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif
