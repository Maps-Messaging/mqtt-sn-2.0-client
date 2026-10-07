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

#ifndef MQTT_SN_2_MQTTSN_H
#define MQTT_SN_2_MQTTSN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MQTTSN_MAX_PACKET_SIZE 65535u

typedef enum {
  MQTTSN_OK = 0,
  MQTTSN_NEED_MORE = 1,
  MQTTSN_INVALID_ARGUMENT = -1,
  MQTTSN_MALFORMED_PACKET = -2,
  MQTTSN_RESERVED_TYPE = -3,
  MQTTSN_BUFFER_TOO_SMALL = -4,
  MQTTSN_STATE_ERROR = -5,
  MQTTSN_FLOW_CONTROL = -6
} mqttsn_status_t;

typedef enum {
  MQTTSN_CONNECT = 0x01,
  MQTTSN_CONNACK = 0x02,
  MQTTSN_PUBLISH = 0x03,
  MQTTSN_PUBACK = 0x04,
  MQTTSN_PUBREC = 0x05,
  MQTTSN_PUBREL = 0x06,
  MQTTSN_PUBCOMP = 0x07,
  MQTTSN_SUBSCRIBE = 0x08,
  MQTTSN_SUBACK = 0x09,
  MQTTSN_UNSUBSCRIBE = 0x0A,
  MQTTSN_UNSUBACK = 0x0B,
  MQTTSN_PINGREQ = 0x0C,
  MQTTSN_PINGRESP = 0x0D,
  MQTTSN_DISCONNECT = 0x0E,
  MQTTSN_AUTH = 0x0F,
  MQTTSN_REGISTER = 0x10,
  MQTTSN_REGACK = 0x11,
  MQTTSN_PUBWOS = 0x12,
  MQTTSN_SLEEPREQ = 0x13,
  MQTTSN_SLEEPRESP = 0x14,
  MQTTSN_WAKEUP = 0x15,
  MQTTSN_ADVERTISE = 0x16,
  MQTTSN_SEARCHGW = 0x17,
  MQTTSN_GWINFO = 0x18,
  MQTTSN_FORWARDER_ENCAPSULATION = 0xFC,
  MQTTSN_CONNECTION_ENCAPSULATION = 0xFE,
  MQTTSN_PROTECTION_ENCAPSULATION = 0xFF
} mqttsn_packet_type_t;

typedef struct {
  mqttsn_packet_type_t type;
  const uint8_t *body;
  size_t body_length;
  size_t packet_length;
  size_t header_length;
} mqttsn_packet_view_t;

/*
 * MQTT-SN 2.0 CSD01 section 2.1.3.
 * Returns non-zero only for packet type values defined by the specification.
 */
int mqttsn_packet_type_is_defined(uint8_t type);

/*
 * Decode exactly one packet at the beginning of input.
 *
 * MQTT-SN-2.1.2-1 requires support for both one-byte and three-byte
 * Length encodings.
 *
 * On MQTTSN_OK, consumed contains the complete packet length.
 * On MQTTSN_NEED_MORE, consumed is zero.
 */
mqttsn_status_t mqttsn_decode_packet(
    const uint8_t *input,
    size_t input_length,
    mqttsn_packet_view_t *packet,
    size_t *consumed);


typedef struct {
  const uint8_t *data;
  size_t length;
} mqttsn_buffer_t;

/*
 * Encode one MQTT-SN Control Packet from multiple body buffers. This is the
 * canonical zero-allocation scatter/gather path used by typed packet codecs.
 */
mqttsn_status_t mqttsn_encode_packetv(
    mqttsn_packet_type_t type,
    const mqttsn_buffer_t *parts,
    size_t part_count,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

/*
 * Encode one control packet from a type and already-encoded packet body.
 * The shortest length representation is emitted.
 */
mqttsn_status_t mqttsn_encode_packet(
    mqttsn_packet_type_t type,
    const uint8_t *body,
    size_t body_length,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);


typedef struct {
  uint8_t clean_start;
  uint8_t allow_network_address_changes;
  uint8_t allow_server_suggested_values;
  uint16_t packet_identifier;
  uint16_t keep_alive;
  uint16_t maximum_packet_size;
  const uint8_t *client_identifier;
  size_t client_identifier_length;
} mqttsn_connect_options_t;

typedef struct {
  uint8_t session_present;
  uint16_t packet_identifier;
  uint8_t reason_code;
  uint8_t has_session_expiry_interval;
  uint32_t session_expiry_interval;
  uint8_t has_server_keep_alive;
  uint16_t server_keep_alive;
  uint8_t has_authentication;
  const uint8_t *authentication_method;
  size_t authentication_method_length;
  const uint8_t *authentication_data;
  size_t authentication_data_length;
  const uint8_t *assigned_client_identifier;
  size_t assigned_client_identifier_length;
} mqttsn_connack_view_t;

/*
 * Validate MQTT-SN UTF-8 according to MQTT-SN-1.8.4-1 and
 * MQTT-SN-1.8.4-2. U+FEFF is accepted and preserved as required by
 * MQTT-SN-1.8.4-3.
 */
int mqttsn_utf8_is_valid(const uint8_t *data, size_t length);


/*
 * Topic validation from MQTT-SN 2.0 CSD01 section 4.7.
 */
int mqttsn_topic_name_is_valid(const uint8_t *data, size_t length);
int mqttsn_topic_filter_is_valid(const uint8_t *data, size_t length);

/*
 * Encode the mandatory CONNECT fields plus an optional Client Identifier.
 * Will, Authentication, Session Expiry and Maximum Awake Messages are
 * separate extensions to this structure and are not silently emitted.
 *
 * Enforces MQTT-SN-2.2-1, MQTT-SN-3.1.2-1, MQTT-SN-3.1.5-1,
 * MQTT-SN-3.1.6-4, MQTT-SN-3.1.7-1 and MQTT-SN-3.1.18-1.
 */
mqttsn_status_t mqttsn_encode_connect(
    const mqttsn_connect_options_t *options,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

/*
 * Decode and validate a CONNACK body received from a Server.
 *
 * Enforces reserved flag validation (MQTT-SN-3.2.2-2), optional-field
 * presence rules, and the Session Present/non-success constraint
 * MQTT-SN-3.2.2.1-5.
 */
mqttsn_status_t mqttsn_decode_connack(
    const mqttsn_packet_view_t *packet,
    mqttsn_connack_view_t *connack);

typedef mqttsn_status_t (*mqttsn_packet_handler_t)(
    void *context,
    const mqttsn_packet_view_t *packet);

/*
 * Process all complete MQTT-SN packets present in input without owning or
 * retaining the input buffer. The handler is called synchronously.
 *
 * If the final packet is incomplete, MQTTSN_NEED_MORE is returned and
 * consumed reports the number of bytes consumed before that packet.
 */
mqttsn_status_t mqttsn_process_input(
    const uint8_t *input,
    size_t input_length,
    mqttsn_packet_handler_t handler,
    void *context,
    size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif
