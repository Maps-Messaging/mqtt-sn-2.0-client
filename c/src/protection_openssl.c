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

#include "mqttsn/protection_openssl.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <string.h>

static int supports(void *user_data, uint8_t scheme) {
  (void)user_data;
  return (scheme <= 0x04u) || (scheme >= 0x40u && scheme <= 0x49u);
}

static int authentication_only(void *user_data, uint8_t scheme) {
  (void)user_data;
  return scheme <= 0x04u;
}

static size_t nominal_tag_length(uint8_t scheme) {
  switch (scheme) {
    case 0x00u:
    case 0x01u:
      return 32u;
    case 0x02u:
    case 0x03u:
    case 0x04u:
      return 16u;
    case 0x40u:
    case 0x41u:
    case 0x42u:
      return 8u;
    case 0x43u:
    case 0x44u:
    case 0x45u:
    case 0x46u:
    case 0x47u:
    case 0x48u:
    case 0x49u:
      return 16u;
    default:
      return 0u;
  }
}

static size_t tag_length(void *user_data, uint8_t scheme, uint8_t code) {
  size_t nominal;
  (void)user_data;

  if (!supports(NULL, scheme) || code == 0x02u || code == 0x03u) {
    return 0u;
  }

  nominal = nominal_tag_length(scheme);
  if (!authentication_only(NULL, scheme)) {
    return code == 0x01u ? nominal : 0u;
  }

  if (code == 0x00u || code == 0x01u) {
    return nominal;
  }
  if (code >= 0x04u) {
    size_t truncated = (size_t)code * 2u;
    return truncated <= nominal ? truncated : 0u;
  }
  return 0u;
}

static size_t protected_length(
    void *user_data,
    uint8_t scheme,
    size_t mqttsn_packet_length) {
  (void)user_data;
  return supports(NULL, scheme) ? mqttsn_packet_length : 0u;
}

static size_t expected_key_length(uint8_t scheme) {
  switch (scheme) {
    case 0x02u:
    case 0x40u:
    case 0x43u:
    case 0x46u:
      return 16u;
    case 0x03u:
    case 0x41u:
    case 0x44u:
    case 0x47u:
      return 24u;
    case 0x04u:
    case 0x42u:
    case 0x45u:
    case 0x48u:
    case 0x49u:
      return 32u;
    case 0x00u:
    case 0x01u:
      return (size_t)-1;
    default:
      return 0u;
  }
}

static mqttsn_status_t resolve_key(
    mqttsn_openssl_provider_t *provider,
    const mqttsn_protection_context_t *context,
    const uint8_t **key,
    size_t *key_length) {
  size_t expected;
  mqttsn_status_t status;

  if (provider == NULL || provider->key_resolver == NULL ||
      key == NULL || key_length == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  status = provider->key_resolver(
      provider->key_user_data, context, key, key_length);
  if (status != MQTTSN_OK || *key == NULL || *key_length == 0u) {
    return status == MQTTSN_OK ? MQTTSN_MALFORMED_PACKET : status;
  }

  expected = expected_key_length(context->scheme);
  if (expected == (size_t)-1) {
    return MQTTSN_OK;
  }
  return *key_length == expected ? MQTTSN_OK : MQTTSN_MALFORMED_PACKET;
}

static mqttsn_status_t compute_mac(
    const mqttsn_protection_context_t *context,
    const uint8_t *key,
    size_t key_length,
    const uint8_t *packet,
    size_t packet_length,
    uint8_t *output,
    size_t *output_length) {
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[2];
  char *name = NULL;
  char *cipher = NULL;
  size_t written = 0u;
  int ok = 0;

  if (context->scheme == 0x00u || context->scheme == 0x01u) {
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    name = context->scheme == 0x00u ? "SHA256" : "SHA3-256";
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, name, 0u);
  } else {
    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    switch (context->scheme) {
      case 0x02u:
        cipher = "AES-128-CBC";
        break;
      case 0x03u:
        cipher = "AES-192-CBC";
        break;
      case 0x04u:
        cipher = "AES-256-CBC";
        break;
      default:
        return MQTTSN_MALFORMED_PACKET;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_CIPHER, cipher, 0u);
  }
  params[1] = OSSL_PARAM_construct_end();

  if (mac == NULL) {
    return MQTTSN_MALFORMED_PACKET;
  }
  ctx = EVP_MAC_CTX_new(mac);
  if (ctx != NULL &&
      EVP_MAC_init(ctx, key, key_length, params) == 1 &&
      EVP_MAC_update(
          ctx,
          context->authenticated_prefix,
          context->authenticated_prefix_length) == 1 &&
      EVP_MAC_update(ctx, packet, packet_length) == 1 &&
      EVP_MAC_final(ctx, output, &written, 64u) == 1) {
    ok = 1;
  }

  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  if (!ok) {
    return MQTTSN_MALFORMED_PACKET;
  }
  *output_length = written;
  return MQTTSN_OK;
}

static const EVP_CIPHER *cipher_for_scheme(uint8_t scheme) {
  switch (scheme) {
    case 0x40u:
    case 0x43u:
      return EVP_aes_128_ccm();
    case 0x41u:
    case 0x44u:
      return EVP_aes_192_ccm();
    case 0x42u:
    case 0x45u:
      return EVP_aes_256_ccm();
    case 0x46u:
      return EVP_aes_128_gcm();
    case 0x47u:
      return EVP_aes_192_gcm();
    case 0x48u:
      return EVP_aes_256_gcm();
    case 0x49u:
      return EVP_chacha20_poly1305();
    default:
      return NULL;
  }
}

static mqttsn_status_t derive_nonce(
    const mqttsn_protection_context_t *context,
    uint8_t *nonce,
    size_t *nonce_length) {
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0u;
  size_t length;

  if (EVP_Digest(
          context->authenticated_prefix,
          context->authenticated_prefix_length,
          digest,
          &digest_length,
          EVP_sha256(),
          NULL) != 1) {
    return MQTTSN_MALFORMED_PACKET;
  }

  length = context->scheme <= 0x45u ? 13u : 12u;
  if (digest_length < length) {
    return MQTTSN_MALFORMED_PACKET;
  }
  memcpy(nonce, digest, length);
  *nonce_length = length;
  return MQTTSN_OK;
}

static mqttsn_status_t aead_encrypt(
    const mqttsn_protection_context_t *context,
    const uint8_t *key,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_written,
    uint8_t *tag,
    size_t tag_capacity,
    size_t *tag_written) {
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = cipher_for_scheme(context->scheme);
  uint8_t nonce[13];
  size_t nonce_length = 0u;
  size_t required_tag = tag_length(NULL, context->scheme, context->tag_length_code);
  int length = 0;
  int total = 0;
  int ok = 0;
  int is_ccm = context->scheme >= 0x40u && context->scheme <= 0x45u;

  if (cipher == NULL || ciphertext_capacity < plaintext_length ||
      tag_capacity < required_tag ||
      derive_nonce(context, nonce, &nonce_length) != MQTTSN_OK) {
    return MQTTSN_MALFORMED_PACKET;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_length, NULL) != 1) {
    goto cleanup;
  }
  if (is_ccm &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)required_tag, NULL) != 1) {
    goto cleanup;
  }
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    goto cleanup;
  }
  if (is_ccm &&
      EVP_EncryptUpdate(ctx, NULL, &length, NULL, (int)plaintext_length) != 1) {
    goto cleanup;
  }
  if (EVP_EncryptUpdate(
          ctx, NULL, &length,
          context->authenticated_prefix,
          (int)context->authenticated_prefix_length) != 1) {
    goto cleanup;
  }
  if (EVP_EncryptUpdate(
          ctx, ciphertext, &length, plaintext, (int)plaintext_length) != 1) {
    goto cleanup;
  }
  total = length;
  if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &length) != 1) {
    goto cleanup;
  }
  total += length;
  if (EVP_CIPHER_CTX_ctrl(
          ctx, EVP_CTRL_AEAD_GET_TAG, (int)required_tag, tag) != 1) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) {
    return MQTTSN_MALFORMED_PACKET;
  }
  *ciphertext_written = (size_t)total;
  *tag_written = required_tag;
  return MQTTSN_OK;
}

static mqttsn_status_t aead_decrypt(
    const mqttsn_protection_context_t *context,
    const uint8_t *key,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t *tag,
    size_t tag_length_value,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_written) {
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = cipher_for_scheme(context->scheme);
  uint8_t nonce[13];
  size_t nonce_length = 0u;
  int length = 0;
  int total = 0;
  int ok = 0;
  int is_ccm = context->scheme >= 0x40u && context->scheme <= 0x45u;

  if (cipher == NULL || plaintext_capacity < ciphertext_length ||
      derive_nonce(context, nonce, &nonce_length) != MQTTSN_OK) {
    return MQTTSN_MALFORMED_PACKET;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return MQTTSN_MALFORMED_PACKET;
  }

  if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_length, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(
          ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_length_value, (void *)tag) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    goto cleanup;
  }

  if (is_ccm &&
      EVP_DecryptUpdate(ctx, NULL, &length, NULL, (int)ciphertext_length) != 1) {
    goto cleanup;
  }
  if (EVP_DecryptUpdate(
          ctx, NULL, &length,
          context->authenticated_prefix,
          (int)context->authenticated_prefix_length) != 1) {
    goto cleanup;
  }
  if (EVP_DecryptUpdate(
          ctx, plaintext, &length, ciphertext, (int)ciphertext_length) != 1) {
    goto cleanup;
  }
  total = length;

  if (!is_ccm) {
    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &length) != 1) {
      goto cleanup;
    }
    total += length;
  }
  ok = 1;

cleanup:
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) {
    return MQTTSN_MALFORMED_PACKET;
  }
  *plaintext_written = (size_t)total;
  return MQTTSN_OK;
}

static mqttsn_status_t protect_cb(
    void *user_data,
    const mqttsn_protection_context_t *context,
    const uint8_t *mqttsn_packet,
    size_t mqttsn_packet_length,
    uint8_t *protected_packet,
    size_t protected_packet_capacity,
    size_t *protected_packet_written,
    uint8_t *authentication_tag,
    size_t authentication_tag_capacity,
    size_t *authentication_tag_written) {
  mqttsn_openssl_provider_t *provider = (mqttsn_openssl_provider_t *)user_data;
  const uint8_t *key = NULL;
  size_t key_length = 0u;
  mqttsn_status_t status;

  status = resolve_key(provider, context, &key, &key_length);
  if (status != MQTTSN_OK) {
    return status;
  }

  if (authentication_only(NULL, context->scheme)) {
    uint8_t full_tag[64];
    size_t full_tag_length = 0u;
    size_t desired = tag_length(NULL, context->scheme, context->tag_length_code);
    if (protected_packet_capacity < mqttsn_packet_length ||
        authentication_tag_capacity < desired) {
      return MQTTSN_BUFFER_TOO_SMALL;
    }
    status = compute_mac(
        context, key, key_length,
        mqttsn_packet, mqttsn_packet_length,
        full_tag, &full_tag_length);
    if (status != MQTTSN_OK || desired == 0u || desired > full_tag_length) {
      return MQTTSN_MALFORMED_PACKET;
    }
    memcpy(protected_packet, mqttsn_packet, mqttsn_packet_length);
    memcpy(authentication_tag, full_tag, desired);
    *protected_packet_written = mqttsn_packet_length;
    *authentication_tag_written = desired;
    return MQTTSN_OK;
  }

  return aead_encrypt(
      context, key,
      mqttsn_packet, mqttsn_packet_length,
      protected_packet, protected_packet_capacity, protected_packet_written,
      authentication_tag, authentication_tag_capacity, authentication_tag_written);
}

static mqttsn_status_t unprotect_cb(
    void *user_data,
    const mqttsn_protection_context_t *context,
    const uint8_t *protected_packet,
    size_t protected_packet_length,
    const uint8_t *authentication_tag,
    size_t authentication_tag_length,
    uint8_t *mqttsn_packet,
    size_t mqttsn_packet_capacity,
    size_t *mqttsn_packet_written) {
  mqttsn_openssl_provider_t *provider = (mqttsn_openssl_provider_t *)user_data;
  const uint8_t *key = NULL;
  size_t key_length = 0u;
  mqttsn_status_t status;

  status = resolve_key(provider, context, &key, &key_length);
  if (status != MQTTSN_OK) {
    return status;
  }

  if (authentication_only(NULL, context->scheme)) {
    uint8_t full_tag[64];
    size_t full_tag_length = 0u;
    if (mqttsn_packet_capacity < protected_packet_length) {
      return MQTTSN_BUFFER_TOO_SMALL;
    }
    status = compute_mac(
        context, key, key_length,
        protected_packet, protected_packet_length,
        full_tag, &full_tag_length);
    if (status != MQTTSN_OK ||
        authentication_tag_length > full_tag_length ||
        CRYPTO_memcmp(
            full_tag, authentication_tag, authentication_tag_length) != 0) {
      return MQTTSN_MALFORMED_PACKET;
    }
    memcpy(mqttsn_packet, protected_packet, protected_packet_length);
    *mqttsn_packet_written = protected_packet_length;
    return MQTTSN_OK;
  }

  return aead_decrypt(
      context, key,
      protected_packet, protected_packet_length,
      authentication_tag, authentication_tag_length,
      mqttsn_packet, mqttsn_packet_capacity, mqttsn_packet_written);
}

mqttsn_status_t mqttsn_openssl_provider_init(
    mqttsn_openssl_provider_t *provider,
    mqttsn_openssl_key_resolver_t key_resolver,
    void *key_user_data) {
  if (provider == NULL || key_resolver == NULL) {
    return MQTTSN_INVALID_ARGUMENT;
  }

  memset(provider, 0, sizeof(*provider));
  provider->key_resolver = key_resolver;
  provider->key_user_data = key_user_data;
  provider->provider.user_data = provider;
  provider->provider.supports = supports;
  provider->provider.authentication_only = authentication_only;
  provider->provider.authentication_tag_length = tag_length;
  provider->provider.protected_packet_length = protected_length;
  provider->provider.protect = protect_cb;
  provider->provider.unprotect = unprotect_cb;
  return MQTTSN_OK;
}

const mqttsn_protection_provider_t *mqttsn_openssl_provider(
    mqttsn_openssl_provider_t *provider) {
  return provider == NULL ? NULL : &provider->provider;
}
