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

#ifndef MQTT_SN_2_AUTH_HPP
#define MQTT_SN_2_AUTH_HPP

#include "mqttsn/mqttsn.hpp"

#include <algorithm>
#include <string>
#include <vector>

extern "C" {
#include "mqttsn/auth.h"
}

namespace mqttsn {

class AuthenticationMechanism {
 public:
  virtual ~AuthenticationMechanism() = default;

  virtual std::string_view method() const = 0;
  virtual std::vector<std::uint8_t> initialResponse() = 0;
  virtual std::vector<std::uint8_t> evaluateChallenge(
      std::span<const std::uint8_t> challenge) = 0;
  virtual bool complete() const = 0;
  virtual void reset() {}
};

struct AuthenticationResponse {
  std::uint16_t packetIdentifier{};
  std::uint8_t reasonCode{};
  std::string authenticationMethod;
  std::vector<std::uint8_t> authenticationData;
};

class AuthenticationExchange {
 public:
  explicit AuthenticationExchange(AuthenticationMechanism& mechanism)
      : bridge_(mechanism) {
    const auto nativeMechanism = bridge_.native();
    mechanism_ = nativeMechanism;
    const auto status = mqttsn_auth_exchange_init(&exchange_, &mechanism_);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
  }

  std::vector<std::uint8_t> initialResponse() {
    std::vector<std::uint8_t> output(0xFFFFu);
    std::size_t written = 0;
    const auto status = mqttsn_auth_exchange_initial_response(
        &exchange_, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  AuthenticationResponse continueAuthentication(
      const AuthPacket& serverAuth,
      std::uint16_t responsePacketIdentifier) {
    const mqttsn_auth_t nativeServer{
        serverAuth.packetIdentifier,
        serverAuth.reasonCode,
        reinterpret_cast<const std::uint8_t*>(
            serverAuth.authenticationMethod.data()),
        serverAuth.authenticationMethod.size(),
        serverAuth.authenticationData.data(),
        serverAuth.authenticationData.size()};

    std::vector<std::uint8_t> response(0xFFFFu);
    std::size_t written = 0;
    mqttsn_auth_t client{};
    const auto status = mqttsn_auth_exchange_continue(
        &exchange_,
        &nativeServer,
        responsePacketIdentifier,
        response.data(),
        response.size(),
        &written,
        &client);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }

    response.resize(written);
    return AuthenticationResponse{
        client.packet_identifier,
        client.reason_code,
        std::string(
            reinterpret_cast<const char*>(client.authentication_method),
            client.authentication_method_length),
        std::move(response)};
  }

  void acceptConnAck(const ConnAckView& connAck) {
    const mqttsn_connack_view_t native{
        static_cast<std::uint8_t>(connAck.sessionPresent),
        connAck.packetIdentifier,
        connAck.reasonCode,
        static_cast<std::uint8_t>(connAck.hasSessionExpiryInterval),
        connAck.sessionExpiryInterval,
        static_cast<std::uint8_t>(connAck.hasServerKeepAlive),
        connAck.serverKeepAlive,
        static_cast<std::uint8_t>(connAck.hasAuthentication),
        reinterpret_cast<const std::uint8_t*>(
            connAck.authenticationMethod.data()),
        connAck.authenticationMethod.size(),
        connAck.authenticationData.data(),
        connAck.authenticationData.size(),
        reinterpret_cast<const std::uint8_t*>(
            connAck.assignedClientIdentifier.data()),
        connAck.assignedClientIdentifier.size()};

    std::vector<std::uint8_t> scratch(0xFFFFu);
    const auto status = mqttsn_auth_exchange_accept_connack(
        &exchange_, &native, scratch.data(), scratch.size());
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
  }

  AuthenticationResponse beginReauthentication(std::uint16_t packetIdentifier) {
    std::vector<std::uint8_t> response(0xFFFFu);
    std::size_t written = 0;
    mqttsn_auth_t client{};

    const auto status = mqttsn_auth_exchange_begin_reauthentication(
        &exchange_,
        packetIdentifier,
        response.data(),
        response.size(),
        &written,
        &client);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }

    response.resize(written);
    return AuthenticationResponse{
        client.packet_identifier,
        client.reason_code,
        std::string(
            reinterpret_cast<const char*>(client.authentication_method),
            client.authentication_method_length),
        std::move(response)};
  }

  [[nodiscard]] bool active() const noexcept {
    return exchange_.active != 0;
  }

  void reset() {
    mqttsn_auth_exchange_reset(&exchange_);
  }

 private:
  class Bridge {
   public:
    explicit Bridge(AuthenticationMechanism& mechanism) : mechanism_(mechanism) {}

    mqttsn_auth_mechanism_t native() {
      const auto method = mechanism_.method();
      mqttsn_auth_mechanism_t result{};
      result.user_data = this;
      result.method = reinterpret_cast<const std::uint8_t*>(method.data());
      result.method_length = method.size();
      result.initial_response = &initialResponse;
      result.evaluate_challenge = &evaluateChallenge;
      result.complete = &complete;
      result.reset = &reset;
      return result;
    }

   private:
    static Bridge& self(void* userData) {
      return *static_cast<Bridge*>(userData);
    }

    static mqttsn_status_t copyResponse(
        const std::vector<std::uint8_t>& response,
        std::uint8_t* output,
        std::size_t outputCapacity,
        std::size_t* written) {
      if (response.size() > outputCapacity) {
        return MQTTSN_BUFFER_TOO_SMALL;
      }
      std::copy(response.begin(), response.end(), output);
      *written = response.size();
      return MQTTSN_OK;
    }

    static mqttsn_status_t initialResponse(
        void* userData,
        std::uint8_t* output,
        std::size_t outputCapacity,
        std::size_t* written) {
      try {
        return copyResponse(
            self(userData).mechanism_.initialResponse(),
            output, outputCapacity, written);
      } catch (...) {
        return MQTTSN_STATE_ERROR;
      }
    }

    static mqttsn_status_t evaluateChallenge(
        void* userData,
        const std::uint8_t* challenge,
        std::size_t challengeLength,
        std::uint8_t* output,
        std::size_t outputCapacity,
        std::size_t* written) {
      try {
        return copyResponse(
            self(userData).mechanism_.evaluateChallenge(
                std::span<const std::uint8_t>(challenge, challengeLength)),
            output, outputCapacity, written);
      } catch (...) {
        return MQTTSN_STATE_ERROR;
      }
    }

    static int complete(void* userData) {
      return self(userData).mechanism_.complete() ? 1 : 0;
    }

    static void reset(void* userData) {
      self(userData).mechanism_.reset();
    }

    AuthenticationMechanism& mechanism_;
  };

  Bridge bridge_;
  mqttsn_auth_mechanism_t mechanism_{};
  mqttsn_auth_exchange_t exchange_{};
};

}  // namespace mqttsn

#endif
