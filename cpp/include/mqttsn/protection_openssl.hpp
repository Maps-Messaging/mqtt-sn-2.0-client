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

#ifndef MQTT_SN_2_PROTECTION_OPENSSL_HPP
#define MQTT_SN_2_PROTECTION_OPENSSL_HPP

#include "mqttsn/mqttsn.hpp"

#include <functional>
#include <mutex>
#include <vector>

extern "C" {
#include "mqttsn/protection_openssl.h"
}

namespace mqttsn {

class OpenSslProtectionProvider final : public ProtectionProvider {
 public:
  using KeyResolver =
      std::function<std::vector<std::uint8_t>(const ProtectionContext&)>;

  explicit OpenSslProtectionProvider(KeyResolver resolver)
      : resolver_(std::move(resolver)) {
    if (!resolver_) {
      throw std::invalid_argument("resolver");
    }
    const auto status = mqttsn_openssl_provider_init(
        &native_, &resolveKey, this);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
  }

  bool supports(std::uint8_t scheme) const override {
    const auto* provider =
        mqttsn_openssl_provider(const_cast<mqttsn_openssl_provider_t*>(&native_));
    return provider->supports(provider->user_data, scheme) != 0;
  }

  bool authenticationOnly(std::uint8_t scheme) const override {
    const auto* provider =
        mqttsn_openssl_provider(const_cast<mqttsn_openssl_provider_t*>(&native_));
    return provider->authentication_only(provider->user_data, scheme) != 0;
  }

  std::size_t authenticationTagLength(
      std::uint8_t scheme,
      std::uint8_t tagLengthCode) const override {
    const auto* provider =
        mqttsn_openssl_provider(const_cast<mqttsn_openssl_provider_t*>(&native_));
    return provider->authentication_tag_length(
        provider->user_data, scheme, tagLengthCode);
  }

  std::size_t protectedPacketLength(
      std::uint8_t scheme,
      std::size_t mqttSnPacketLength) const override {
    const auto* provider =
        mqttsn_openssl_provider(const_cast<mqttsn_openssl_provider_t*>(&native_));
    return provider->protected_packet_length(
        provider->user_data, scheme, mqttSnPacketLength);
  }

  ProtectedContent protect(
      const ProtectionContext& context,
      std::span<const std::uint8_t> mqttSnPacket) override {
    std::scoped_lock lock(mutex_);
    const auto* provider = mqttsn_openssl_provider(&native_);
    const auto nativeContext = toNative(context);

    std::vector<std::uint8_t> protectedPacket(
        protectedPacketLength(context.scheme, mqttSnPacket.size()));
    std::vector<std::uint8_t> tag(
        authenticationTagLength(context.scheme, context.tagLengthCode));
    std::size_t protectedWritten = 0;
    std::size_t tagWritten = 0;

    const auto status = provider->protect(
        provider->user_data,
        &nativeContext,
        mqttSnPacket.data(),
        mqttSnPacket.size(),
        protectedPacket.data(),
        protectedPacket.size(),
        &protectedWritten,
        tag.data(),
        tag.size(),
        &tagWritten);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }

    protectedPacket.resize(protectedWritten);
    tag.resize(tagWritten);
    return ProtectedContent{std::move(protectedPacket), std::move(tag)};
  }

  std::vector<std::uint8_t> unprotect(
      const ProtectionContext& context,
      std::span<const std::uint8_t> protectedPacket,
      std::span<const std::uint8_t> authenticationTag) override {
    std::scoped_lock lock(mutex_);
    const auto* provider = mqttsn_openssl_provider(&native_);
    const auto nativeContext = toNative(context);

    std::vector<std::uint8_t> plaintext(protectedPacket.size());
    std::size_t written = 0;
    const auto status = provider->unprotect(
        provider->user_data,
        &nativeContext,
        protectedPacket.data(),
        protectedPacket.size(),
        authenticationTag.data(),
        authenticationTag.size(),
        plaintext.data(),
        plaintext.size(),
        &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }

    plaintext.resize(written);
    return plaintext;
  }

 private:
  static mqttsn_status_t resolveKey(
      void* userData,
      const mqttsn_protection_context_t* context,
      const std::uint8_t** key,
      std::size_t* keyLength) {
    auto& self = *static_cast<OpenSslProtectionProvider*>(userData);
    try {
      self.keyBuffer_ = self.resolver_(toCpp(*context));
      if (self.keyBuffer_.empty()) {
        return MQTTSN_MALFORMED_PACKET;
      }
      *key = self.keyBuffer_.data();
      *keyLength = self.keyBuffer_.size();
      return MQTTSN_OK;
    } catch (...) {
      return MQTTSN_MALFORMED_PACKET;
    }
  }

  static mqttsn_protection_context_t toNative(
      const ProtectionContext& context) {
    return mqttsn_protection_context_t{
        context.scheme,
        context.tagLengthCode,
        context.senderIdentifier.data(),
        context.senderIdentifier.size(),
        context.random.data(),
        context.random.size(),
        context.cryptographicMaterial.data(),
        context.cryptographicMaterial.size(),
        context.monotonicCounter.data(),
        context.monotonicCounter.size(),
        context.authenticatedPrefix.data(),
        context.authenticatedPrefix.size()};
  }

  static ProtectionContext toCpp(
      const mqttsn_protection_context_t& context) {
    return ProtectionContext{
        context.scheme,
        context.tag_length_code,
        std::span<const std::uint8_t>(
            context.sender_identifier, context.sender_identifier_length),
        std::span<const std::uint8_t>(
            context.random, context.random_length),
        std::span<const std::uint8_t>(
            context.cryptographic_material,
            context.cryptographic_material_length),
        std::span<const std::uint8_t>(
            context.monotonic_counter, context.monotonic_counter_length),
        std::span<const std::uint8_t>(
            context.authenticated_prefix,
            context.authenticated_prefix_length)};
  }

  KeyResolver resolver_;
  mqttsn_openssl_provider_t native_{};
  std::vector<std::uint8_t> keyBuffer_;
  mutable std::mutex mutex_;
};

}  // namespace mqttsn

#endif
