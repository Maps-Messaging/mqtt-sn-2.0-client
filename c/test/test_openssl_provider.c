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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  const uint8_t *key;
  size_t key_length;
} key_data_t;

typedef struct {
  uint8_t scheme;
  const char *key_hex;
  const char *protected_hex;
  const char *tag_hex;
} vector_t;

static const uint8_t PREFIX[] = {
    0x12,0x00,0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
};
static const uint8_t PLAINTEXT[] = {0x04,0x0C,0x12,0x34};

static const vector_t VECTORS[] = {
    {0x00u, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "040c1234", "a3ae047cd0fb77256f6cbf12252733dd73075a9622780fc95be7ee03490dc8db"},
    {0x01u, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "040c1234", "130a16c674d3af9ee2d24dda7ec65c8e3c89806cea699ef621150b493e57861e"},
    {0x02u, "2b7e151628aed2a6abf7158809cf4f3c", "040c1234", "a3e0372ca6e9ca552f310f01d9f00ba5"},
    {0x03u, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "040c1234", "94d95a579745229a5a2d0f54dda3f6d1"},
    {0x04u, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "040c1234", "791d72eaec7fd5ce0ecd112749a05673"},
    {0x40u, "404142434445464748494a4b4c4d4e4f", "04dfc15b", "0e3b59a345150593"},
    {0x41u, "404142434445464748494a4b4c4d4e4f5051525354555657", "2bdf29ea", "14ea27013b24bb50"},
    {0x42u, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "358b3d1b", "387c8791681e3ed9"},
    {0x43u, "404142434445464748494a4b4c4d4e4f", "04dfc15b", "577798b5f0e31ea24da56dd805a68cc5"},
    {0x44u, "404142434445464748494a4b4c4d4e4f5051525354555657", "2bdf29ea", "600a13e6d7df0147d80564432d4ccaaa"},
    {0x45u, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "358b3d1b", "9b002a22ba6e2f6f7e6748b88d42bf5c"},
    {0x46u, "00000000000000000000000000000000", "2743129d", "dffa819c4fe6d41c4912a891e4c82786"},
    {0x47u, "000000000000000000000000000000000000000000000000", "631721b8", "e9a8babec89fb68f883d19425498d4cc"},
    {0x48u, "0000000000000000000000000000000000000000000000000000000000000000", "a9fa1bbd", "79f9e5b15a075aa22bece93beb9722cf"},
    {0x49u, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "c1816b5e", "4979d51cd6ebd3132aecb6c366360ada"}
};

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t decode_hex(const char *hex, uint8_t *out, size_t capacity) {
  size_t length = strlen(hex) / 2u;
  size_t i;
  assert(strlen(hex) % 2u == 0u);
  assert(length <= capacity);
  for (i = 0u; i < length; i++) {
    int high = hex_value(hex[i * 2u]);
    int low = hex_value(hex[i * 2u + 1u]);
    assert(high >= 0 && low >= 0);
    out[i] = (uint8_t)((high << 4) | low);
  }
  return length;
}

static mqttsn_status_t resolve_key(
    void *user_data,
    const mqttsn_protection_context_t *context,
    const uint8_t **key,
    size_t *key_length) {
  key_data_t *data = (key_data_t *)user_data;
  (void)context;
  *key = data->key;
  *key_length = data->key_length;
  return MQTTSN_OK;
}

static void test_vectors(void) {
  size_t i;

  for (i = 0u; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
    uint8_t key[64];
    uint8_t expected_protected[64];
    uint8_t expected_tag[64];
    uint8_t protected_packet[64];
    uint8_t tag[64];
    uint8_t plain[64];
    size_t key_length = decode_hex(VECTORS[i].key_hex, key, sizeof(key));
    size_t expected_protected_length =
        decode_hex(VECTORS[i].protected_hex, expected_protected, sizeof(expected_protected));
    size_t expected_tag_length =
        decode_hex(VECTORS[i].tag_hex, expected_tag, sizeof(expected_tag));
    size_t protected_written = 0u;
    size_t tag_written = 0u;
    size_t plain_written = 0u;
    key_data_t key_data = {key, key_length};
    mqttsn_openssl_provider_t openssl_provider;
    const mqttsn_protection_provider_t *provider;
    mqttsn_protection_context_t context = {
        .scheme = VECTORS[i].scheme,
        .tag_length_code = 0x01u,
        .sender_identifier = NULL,
        .sender_identifier_length = 0u,
        .random = NULL,
        .random_length = 0u,
        .cryptographic_material = NULL,
        .cryptographic_material_length = 0u,
        .monotonic_counter = NULL,
        .monotonic_counter_length = 0u,
        .authenticated_prefix = PREFIX,
        .authenticated_prefix_length = sizeof(PREFIX)
    };

    assert(mqttsn_openssl_provider_init(
        &openssl_provider, resolve_key, &key_data) == MQTTSN_OK);
    provider = mqttsn_openssl_provider(&openssl_provider);
    assert(provider != NULL);

    assert(provider->protect(
        provider->user_data,
        &context,
        PLAINTEXT,
        sizeof(PLAINTEXT),
        protected_packet,
        sizeof(protected_packet),
        &protected_written,
        tag,
        sizeof(tag),
        &tag_written) == MQTTSN_OK);

    assert(protected_written == expected_protected_length);
    assert(tag_written == expected_tag_length);
    assert(memcmp(
        protected_packet,
        expected_protected,
        expected_protected_length) == 0);
    assert(memcmp(tag, expected_tag, expected_tag_length) == 0);

    assert(provider->unprotect(
        provider->user_data,
        &context,
        protected_packet,
        protected_written,
        tag,
        tag_written,
        plain,
        sizeof(plain),
        &plain_written) == MQTTSN_OK);
    assert(plain_written == sizeof(PLAINTEXT));
    assert(memcmp(plain, PLAINTEXT, sizeof(PLAINTEXT)) == 0);
  }
}

static void test_truncation_and_tamper(void) {
  uint8_t key[32];
  uint8_t protected_packet[64];
  uint8_t tag[64];
  uint8_t plain[64];
  size_t protected_written = 0u;
  size_t tag_written = 0u;
  size_t plain_written = 0u;
  key_data_t key_data;
  mqttsn_openssl_provider_t openssl_provider;
  const mqttsn_protection_provider_t *provider;
  mqttsn_protection_context_t context = {
      .scheme = 0x00u,
      .tag_length_code = 0x04u,
      .authenticated_prefix = PREFIX,
      .authenticated_prefix_length = sizeof(PREFIX)
  };

  key_data.key_length = decode_hex(
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      key,
      sizeof(key));
  key_data.key = key;
  assert(mqttsn_openssl_provider_init(
      &openssl_provider, resolve_key, &key_data) == MQTTSN_OK);
  provider = mqttsn_openssl_provider(&openssl_provider);

  assert(provider->protect(
      provider->user_data, &context,
      PLAINTEXT, sizeof(PLAINTEXT),
      protected_packet, sizeof(protected_packet), &protected_written,
      tag, sizeof(tag), &tag_written) == MQTTSN_OK);
  assert(tag_written == 8u);

  tag[0] ^= 1u;
  assert(provider->unprotect(
      provider->user_data, &context,
      protected_packet, protected_written,
      tag, tag_written,
      plain, sizeof(plain), &plain_written) == MQTTSN_MALFORMED_PACKET);
}


static void test_envelope_round_trips(void) {
  const uint8_t sender_id[8] = {1,2,3,4,5,6,7,8};
  const uint8_t random[4] = {0x11,0x12,0x13,0x14};
  const uint8_t inner[] = {0x04, MQTTSN_PINGREQ, 0x12, 0x34};
  size_t i;

  for (i = 0u; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
    uint8_t key[64];
    size_t key_length = decode_hex(VECTORS[i].key_hex, key, sizeof(key));
    key_data_t key_data = {key, key_length};
    mqttsn_openssl_provider_t openssl_provider;
    const mqttsn_protection_provider_t *provider;
    mqttsn_protection_envelope_t envelope = {
        .scheme = VECTORS[i].scheme,
        .tag_length_code = 0x01u,
        .sender_identifier = sender_id,
        .sender_identifier_length = sizeof(sender_id),
        .random = random,
        .random_length = sizeof(random),
        .cryptographic_material = NULL,
        .cryptographic_material_length = 0u,
        .monotonic_counter = NULL,
        .monotonic_counter_length = 0u,
        .mqttsn_packet = inner,
        .mqttsn_packet_length = sizeof(inner)
    };
    uint8_t encoded[256];
    size_t encoded_length = 0u;
    uint8_t decoded_inner[64];
    size_t decoded_inner_length = 0u;
    mqttsn_protection_envelope_t decoded;

    assert(mqttsn_openssl_provider_init(
        &openssl_provider, resolve_key, &key_data) == MQTTSN_OK);
    provider = mqttsn_openssl_provider(&openssl_provider);

    assert(mqttsn_encode_protection(
        &envelope,
        provider,
        encoded,
        sizeof(encoded),
        &encoded_length) == MQTTSN_OK);

    assert(mqttsn_decode_protection(
        encoded,
        encoded_length,
        provider,
        decoded_inner,
        sizeof(decoded_inner),
        &decoded_inner_length,
        &decoded) == MQTTSN_OK);

    assert(decoded.scheme == VECTORS[i].scheme);
    assert(decoded_inner_length == sizeof(inner));
    assert(memcmp(decoded_inner, inner, sizeof(inner)) == 0);
  }
}

int main(void) {
  test_vectors();
  test_truncation_and_tamper();
  test_envelope_round_trips();
  return 0;
}
