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

mqttsn_status_t mqttsn_encode_wakeup(
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif
