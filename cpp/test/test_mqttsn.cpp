#include "mqttsn/mqttsn.hpp"

#include <cassert>
#include <cstdint>
#include <vector>

int main() {
  const auto encoded = mqttsn::Codec::encode(mqttsn::PacketType::PingReq);
  assert(encoded.size() == 2u);
  assert(encoded[0] == 0x02u);
  assert(encoded[1] == 0x0Cu);

  const auto decoded = mqttsn::Codec::decode(encoded);
  assert(decoded.type == mqttsn::PacketType::PingReq);
  assert(decoded.body.empty());

  std::vector<std::uint8_t> body(254u, 0x42u);
  const auto extended = mqttsn::Codec::encode(mqttsn::PacketType::Publish, body);
  assert(extended.size() == 258u);
  assert(extended[0] == 0x01u);
  assert(extended[1] == 0x01u);
  assert(extended[2] == 0x02u);
  assert(extended[3] == 0x03u);

  return 0;
}
