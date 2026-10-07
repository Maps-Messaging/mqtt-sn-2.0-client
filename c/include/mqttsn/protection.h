#ifndef MQTT_SN_2_PROTECTION_H
#define MQTT_SN_2_PROTECTION_H

#include "mqttsn/mqttsn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t scheme;
  uint8_t tag_length_code;
  const uint8_t *sender_identifier;
  size_t sender_identifier_length;
  const uint8_t *random;
  size_t random_length;
  const uint8_t *cryptographic_material;
  size_t cryptographic_material_length;
  const uint8_t *monotonic_counter;
  size_t monotonic_counter_length;
  const uint8_t *authenticated_prefix;
  size_t authenticated_prefix_length;
} mqttsn_protection_context_t;

typedef struct {
  void *user_data;

  int (*supports)(void *user_data, uint8_t scheme);
  int (*authentication_only)(void *user_data, uint8_t scheme);

  size_t (*authentication_tag_length)(
      void *user_data,
      uint8_t scheme,
      uint8_t tag_length_code);

  size_t (*protected_packet_length)(
      void *user_data,
      uint8_t scheme,
      size_t mqttsn_packet_length);

  mqttsn_status_t (*protect)(
      void *user_data,
      const mqttsn_protection_context_t *context,
      const uint8_t *mqttsn_packet,
      size_t mqttsn_packet_length,
      uint8_t *protected_packet,
      size_t protected_packet_capacity,
      size_t *protected_packet_written,
      uint8_t *authentication_tag,
      size_t authentication_tag_capacity,
      size_t *authentication_tag_written);

  mqttsn_status_t (*unprotect)(
      void *user_data,
      const mqttsn_protection_context_t *context,
      const uint8_t *protected_packet,
      size_t protected_packet_length,
      const uint8_t *authentication_tag,
      size_t authentication_tag_length,
      uint8_t *mqttsn_packet,
      size_t mqttsn_packet_capacity,
      size_t *mqttsn_packet_written);
} mqttsn_protection_provider_t;

typedef struct {
  uint8_t scheme;
  uint8_t tag_length_code;

  const uint8_t *sender_identifier;
  size_t sender_identifier_length;

  const uint8_t *random;
  size_t random_length;

  const uint8_t *cryptographic_material;
  size_t cryptographic_material_length;

  const uint8_t *monotonic_counter;
  size_t monotonic_counter_length;

  const uint8_t *mqttsn_packet;
  size_t mqttsn_packet_length;
} mqttsn_protection_envelope_t;

mqttsn_status_t mqttsn_encode_protection(
    const mqttsn_protection_envelope_t *envelope,
    const mqttsn_protection_provider_t *provider,
    uint8_t *output,
    size_t output_capacity,
    size_t *written);

mqttsn_status_t mqttsn_decode_protection(
    const uint8_t *input,
    size_t input_length,
    const mqttsn_protection_provider_t *provider,
    uint8_t *mqttsn_packet_output,
    size_t mqttsn_packet_capacity,
    size_t *mqttsn_packet_written,
    mqttsn_protection_envelope_t *envelope);

#ifdef __cplusplus
}
#endif

#endif
