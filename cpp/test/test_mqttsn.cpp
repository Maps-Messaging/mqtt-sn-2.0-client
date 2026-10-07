#include "mqttsn/mqttsn.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

static void test_short_and_extended_framing() {
  const auto encoded = mqttsn::Codec::encode(mqttsn::PacketType::PingReq);
  assert(encoded.size() == 2u);
  assert(encoded[0] == 0x02u);
  assert(encoded[1] == 0x0Cu);

  const auto decoded = mqttsn::Codec::decode(encoded);
  assert(decoded.type == mqttsn::PacketType::PingReq);
  assert(decoded.body.empty());
  assert(decoded.headerLength == 2u);

  std::vector<std::uint8_t> shortBody(253u, 0x42u);
  const auto shortPacket = mqttsn::Codec::encode(
      mqttsn::PacketType::Publish, shortBody);
  assert(shortPacket.size() == 255u);
  assert(shortPacket[0] == 0xFFu);
  assert(mqttsn::Codec::decode(shortPacket).headerLength == 2u);

  std::vector<std::uint8_t> extendedBody(254u, 0x42u);
  const auto extended = mqttsn::Codec::encode(
      mqttsn::PacketType::Publish, extendedBody);
  assert(extended.size() == 258u);
  assert(extended[0] == 0x01u);
  assert(extended[1] == 0x01u);
  assert(extended[2] == 0x02u);
  assert(extended[3] == 0x03u);
  assert(mqttsn::Codec::decode(extended).headerLength == 4u);
}

static void test_connect_and_connack() {
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
}

static void test_connack_authentication_views() {
  const std::vector<std::uint8_t> bytes{
      0x12, 0x02, 0x08, 0x12, 0x34, 0x00,
      0x03, 'p', 's', 'k',
      0x00, 0x02, 0x01, 0x02,
      'i', 'd', '4', '2'};

  const auto packet = mqttsn::Codec::decode(bytes);
  const auto connAck = mqttsn::Codec::decodeConnAck(packet);

  assert(connAck.hasAuthentication);
  assert(connAck.authenticationMethod == "psk");
  assert(connAck.authenticationData.size() == 2u);
  assert(connAck.authenticationData[0] == 0x01u);
  assert(connAck.authenticationData[1] == 0x02u);
  assert(connAck.assignedClientIdentifier == "id42");
}

static void test_invalid_input_reports_native_status() {
  const std::array<std::uint8_t, 2> reserved{0x02u, 0xFDu};
  try {
    (void)mqttsn::Codec::decode(reserved);
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_RESERVED_TYPE);
  }

  const std::array<std::uint8_t, 1> incomplete{0x01u};
  try {
    (void)mqttsn::Codec::decode(incomplete);
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_NEED_MORE);
  }

  const std::vector<std::uint8_t> zeroConnAck{
      0x06, 0x02, 0x00, 0x00, 0x00, 0x00};
  try {
    (void)mqttsn::Codec::decodeConnAck(mqttsn::Codec::decode(zeroConnAck));
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_MALFORMED_PACKET);
  }
}

static void test_connect_validation_is_delegated_to_c() {
  try {
    const mqttsn::ConnectOptions invalid{
        true, false, false, 0u, 60u, 0u, "client"};
    (void)mqttsn::Codec::encodeConnect(invalid);
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_MALFORMED_PACKET);
  }

  try {
    const mqttsn::ConnectOptions invalid{
        true, false, false, 1u, 0u, 0u, "client"};
    (void)mqttsn::Codec::encodeConnect(invalid);
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_MALFORMED_PACKET);
  }
}

static void test_all_packet_types_can_use_generic_framing() {
  const std::array<mqttsn::PacketType, 27> types{
      mqttsn::PacketType::Connect,
      mqttsn::PacketType::ConnAck,
      mqttsn::PacketType::Publish,
      mqttsn::PacketType::PubAck,
      mqttsn::PacketType::PubRec,
      mqttsn::PacketType::PubRel,
      mqttsn::PacketType::PubComp,
      mqttsn::PacketType::Subscribe,
      mqttsn::PacketType::SubAck,
      mqttsn::PacketType::Unsubscribe,
      mqttsn::PacketType::UnsubAck,
      mqttsn::PacketType::PingReq,
      mqttsn::PacketType::PingResp,
      mqttsn::PacketType::Disconnect,
      mqttsn::PacketType::Auth,
      mqttsn::PacketType::Register,
      mqttsn::PacketType::RegAck,
      mqttsn::PacketType::PubWos,
      mqttsn::PacketType::SleepReq,
      mqttsn::PacketType::SleepResp,
      mqttsn::PacketType::Wakeup,
      mqttsn::PacketType::Advertise,
      mqttsn::PacketType::SearchGw,
      mqttsn::PacketType::GwInfo,
      mqttsn::PacketType::ForwarderEncapsulation,
      mqttsn::PacketType::ConnectionEncapsulation,
      mqttsn::PacketType::ProtectionEncapsulation};

  for (const auto type : types) {
    const auto encoded = mqttsn::Codec::encode(type);
    const auto decoded = mqttsn::Codec::decode(encoded);
    assert(decoded.type == type);
  }
}

int main() {
  test_short_and_extended_framing();
  test_connect_and_connack();
  test_connack_authentication_views();
  test_invalid_input_reports_native_status();
  test_connect_validation_is_delegated_to_c();
  test_all_packet_types_can_use_generic_framing();
  return 0;
}
