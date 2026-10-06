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

  const mqttsn::ConnectOptions connect{
      true, false, false, 0x1234u, 60u, 0u, "client1"};
  const auto connectBytes = mqttsn::Codec::encodeConnect(connect);
  const std::vector<std::uint8_t> expectedConnect{
      0x11, 0x01, 0x01, 0x12, 0x34, 0x02, 0x00, 0x3C,
      0x00, 0x00, 'c', 'l', 'i', 'e', 'n', 't', '1'};
  assert(connectBytes == expectedConnect);

  const std::vector<std::uint8_t> connAckBytes{
      0x0C, 0x02, 0x06, 0x12, 0x34, 0x00,
      0x00, 0x00, 0x00, 0x78, 0x00, 0x3C};
  const auto connAckPacket = mqttsn::Codec::decode(connAckBytes);
  const auto connAck = mqttsn::Codec::decodeConnAck(connAckPacket);
  assert(connAck.packetIdentifier == 0x1234u);
  assert(connAck.reasonCode == 0u);
  assert(connAck.hasSessionExpiryInterval);
  assert(connAck.sessionExpiryInterval == 120u);
  assert(connAck.hasServerKeepAlive);
  assert(connAck.serverKeepAlive == 60u);

  return 0;
}
