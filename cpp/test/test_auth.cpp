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

#include "mqttsn/auth.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

class TestMechanism final : public mqttsn::AuthenticationMechanism {
 public:
  std::string_view method() const override {
    return "TEST";
  }

  std::vector<std::uint8_t> initialResponse() override {
    return {0x01u};
  }

  std::vector<std::uint8_t> evaluateChallenge(
      std::span<const std::uint8_t> challenge) override {
    if (challenge.size() == 1u && challenge[0] == 0x7Fu) {
      complete_ = true;
      return {};
    }
    return {0x02u};
  }

  bool complete() const override {
    return complete_;
  }

  void reset() override {
    complete_ = false;
    ++resetCount;
  }

  unsigned resetCount{};

 private:
  bool complete_{};
};

int main() {
  const std::array<std::uint8_t, 3> authData{0x01u,0x02u,0x03u};
  mqttsn::ConnectOptions options{
      true,
      false,
      false,
      0x1234u,
      60u,
      0u,
      "client1",
      "PLAIN",
      authData};

  const auto connect = mqttsn::Codec::encodeConnect(options);
  const std::vector<std::uint8_t> expected{
      0x1C,0x01,0x05,0x12,0x34,0x02,0x00,0x3C,0x00,0x00,
      0x05,'P','L','A','I','N',0x00,0x03,0x01,0x02,0x03,
      'c','l','i','e','n','t','1'};
  assert(connect == expected);

  TestMechanism mechanism;
  mqttsn::AuthenticationExchange exchange(mechanism);
  const auto initial = exchange.initialResponse();
  assert(initial.size() == 1u && initial[0] == 0x01u);

  const std::array<std::uint8_t, 1> challenge{0x10u};
  const mqttsn::AuthPacket server{
      0x1001u, 0x18u, "TEST", challenge};
  const auto response = exchange.continueAuthentication(server, 0x1002u);
  assert(response.reasonCode == 0x18u);
  assert(response.authenticationData.size() == 1u);
  assert(response.authenticationData[0] == 0x02u);

  const std::array<std::uint8_t, 1> finalData{0x7Fu};
  const mqttsn::ConnAckView connack{
      false, 0x1002u, 0u,
      false, 0u,
      false, 0u,
      true, "TEST", finalData, ""};
  exchange.acceptConnAck(connack);
  assert(mechanism.complete());
  assert(!exchange.active());

  const auto reauth = exchange.beginReauthentication(0x2222u);
  assert(reauth.reasonCode == 0x19u);
  assert(mechanism.resetCount == 1u);

  return 0;
}
