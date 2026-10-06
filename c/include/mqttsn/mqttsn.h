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
  MQTTSN_BUFFER_TOO_SMALL = -4
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
