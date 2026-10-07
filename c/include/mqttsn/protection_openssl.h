#ifndef MQTT_SN_2_PROTECTION_OPENSSL_H
#define MQTT_SN_2_PROTECTION_OPENSSL_H

#include "mqttsn/protection.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef mqttsn_status_t (*mqttsn_openssl_key_resolver_t)(
    void *user_data,
    const mqttsn_protection_context_t *context,
    const uint8_t **key,
    size_t *key_length);

typedef struct {
  mqttsn_openssl_key_resolver_t key_resolver;
  void *key_user_data;
  mqttsn_protection_provider_t provider;
} mqttsn_openssl_provider_t;

mqttsn_status_t mqttsn_openssl_provider_init(
    mqttsn_openssl_provider_t *provider,
    mqttsn_openssl_key_resolver_t key_resolver,
    void *key_user_data);

const mqttsn_protection_provider_t *mqttsn_openssl_provider(
    mqttsn_openssl_provider_t *provider);

#ifdef __cplusplus
}
#endif

#endif
