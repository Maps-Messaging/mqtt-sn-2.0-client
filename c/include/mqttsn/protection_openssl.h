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
