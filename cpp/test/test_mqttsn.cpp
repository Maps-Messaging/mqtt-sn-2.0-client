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


static void test_pubwos_and_gateway_discovery_wrappers() {
  const std::array<std::uint8_t, 1> payload{'x'};
  const mqttsn::PubWosPacket pubwos{
      false,
      MQTTSN_TOPIC_NAME,
      0u,
      "a/b",
      payload};
  const auto pubwosBytes = mqttsn::Codec::encodePubWos(pubwos);
  const std::vector<std::uint8_t> expectedPubWos{
      0x09, 0x12, 0x03, 0x00, 0x03, 'a', '/', 'b', 'x'};
  assert(pubwosBytes == expectedPubWos);
  const auto decodedPubWos =
      mqttsn::Codec::decodePubWos(mqttsn::Codec::decode(pubwosBytes));
  assert(decodedPubWos.topicName == "a/b");
  assert(decodedPubWos.payload.size() == 1u);
  assert(decodedPubWos.payload[0] == 'x');

  const auto advertiseBytes =
      mqttsn::Codec::encodeAdvertise(mqttsn::AdvertisePacket{7u, 60u});
  const std::vector<std::uint8_t> expectedAdvertise{
      0x05, 0x16, 0x07, 0x00, 0x3C};
  assert(advertiseBytes == expectedAdvertise);
  const auto advertise =
      mqttsn::Codec::decodeAdvertise(mqttsn::Codec::decode(advertiseBytes));
  assert(advertise.gatewayIdentifier == 7u);
  assert(advertise.durationSeconds == 60u);

  const std::array<std::uint8_t, 2> networkInfo{0x01u, 0x02u};
  const auto searchBytes =
      mqttsn::Codec::encodeSearchGw(mqttsn::SearchGwPacket{networkInfo});
  const std::vector<std::uint8_t> expectedSearch{
      0x04, 0x17, 0x01, 0x02};
  assert(searchBytes == expectedSearch);
  const auto search =
      mqttsn::Codec::decodeSearchGw(mqttsn::Codec::decode(searchBytes));
  assert(search.additionalNetworkInformation.size() == 2u);

  const std::array<std::uint8_t, 4> address{0xC0u, 0xA8u, 0x01u, 0x01u};
  const auto gwInfoBytes =
      mqttsn::Codec::encodeGwInfo(mqttsn::GwInfoPacket{7u, address});
  const std::vector<std::uint8_t> expectedGwInfo{
      0x07, 0x18, 0x07, 0xC0, 0xA8, 0x01, 0x01};
  assert(gwInfoBytes == expectedGwInfo);
  const auto gwInfo =
      mqttsn::Codec::decodeGwInfo(mqttsn::Codec::decode(gwInfoBytes));
  assert(gwInfo.gatewayIdentifier == 7u);
  assert(gwInfo.gatewayAddress.size() == 4u);
}


static void test_timer_wrappers() {
  mqttsn::RetryTimer retry(1000u, 2u);
  retry.start(100u);
  assert(retry.poll(1099u) == mqttsn::RetryAction::None);
  assert(retry.poll(1100u) == mqttsn::RetryAction::Retransmit);
  assert(retry.retriesSent() == 1u);
  assert(retry.poll(2100u) == mqttsn::RetryAction::Retransmit);
  assert(retry.poll(3100u) == mqttsn::RetryAction::DeleteConnection);
  assert(!retry.active());

  mqttsn::KeepAliveTimer keepAlive(1000u);
  keepAlive.start(0u);
  assert(keepAlive.poll(999u) == mqttsn::KeepAliveAction::None);
  keepAlive.outboundActivity(900u);
  assert(keepAlive.poll(1000u) == mqttsn::KeepAliveAction::None);
  assert(keepAlive.poll(1900u) == mqttsn::KeepAliveAction::SendPingReq);
}


static void test_encapsulation_wrappers() {
  const std::array<std::uint8_t, 4> inner{
      0x04u, 0x0Cu, 0x12u, 0x34u};

  const auto connectionBytes = mqttsn::Codec::encodeConnectionEncapsulation(
      mqttsn::ConnectionEncapsulation{"client1", inner});
  const std::vector<std::uint8_t> expectedConnection{
      0x0F, 0xFE, 0x00, 0x07,
      'c', 'l', 'i', 'e', 'n', 't', '1',
      0x04, 0x0C, 0x12, 0x34};
  assert(connectionBytes == expectedConnection);

  const auto connection = mqttsn::Codec::decodeConnectionEncapsulation(
      mqttsn::Codec::decode(connectionBytes));
  assert(connection.clientIdentifier == "client1");
  assert(connection.mqttSnPacket.size() == 4u);

  const std::array<std::uint8_t, 2> addressing{0x01u, 0x02u};
  const auto forwarderBytes = mqttsn::Codec::encodeForwarderEncapsulation(
      mqttsn::ForwarderEncapsulation{addressing, inner});
  const std::vector<std::uint8_t> expectedForwarder{
      0x09, 0xFC, 0x02, 0x01, 0x02, 0x04, 0x0C, 0x12, 0x34};
  assert(forwarderBytes == expectedForwarder);

  const auto forwarder = mqttsn::Codec::decodeForwarderEncapsulation(
      mqttsn::Codec::decode(forwarderBytes));
  assert(forwarder.clientAddressingInformation.size() == 2u);
  assert(forwarder.mqttSnPacket.size() == 4u);

  const std::array<std::uint8_t, 6> connack{
      0x06u, 0x02u, 0x00u, 0x12u, 0x34u, 0x00u};
  try {
    (void)mqttsn::Codec::encodeConnectionEncapsulation(
        mqttsn::ConnectionEncapsulation{"client1", connack});
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_MALFORMED_PACKET);
  }
}


static void test_session_wrapper() {
  mqttsn::Session session;
  const mqttsn::ConnectOptions connect{
      true, false, false, 0x1001u, 60u, 0u, "state-test"};

  const auto connectBytes = mqttsn::Codec::encodeConnect(connect);
  session.trackOutbound(connectBytes);
  assert(session.state() == mqttsn::ClientState::Connecting);

  const std::array<std::uint8_t, 6> connack{
      0x06u, 0x02u, 0x00u, 0x10u, 0x01u, 0x00u};
  session.trackInbound(connack);
  assert(session.state() == mqttsn::ClientState::Active);

  const std::array<std::uint8_t, 4> ping{
      0x04u, 0x0Cu, 0x20u, 0x01u};
  session.trackOutbound(ping);
  assert(session.hasOutboundRequest());
  assert(session.outboundPacketIdentifier() == 0x2001u);

  try {
    const std::array<std::uint8_t, 4> secondPing{
        0x04u, 0x0Cu, 0x20u, 0x02u};
    session.trackOutbound(secondPing);
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_FLOW_CONTROL);
  }

  session.retryExhausted();
  assert(session.state() == mqttsn::ClientState::Disconnected);
  assert(!session.hasOutboundRequest());

  mqttsn::Session wrapping(0xFFFFu);
  assert(wrapping.nextPacketIdentifier() == 0xFFFFu);
  assert(wrapping.nextPacketIdentifier() == 1u);
}


class CopyProtectionProvider final : public mqttsn::ProtectionProvider {
 public:
  bool supports(std::uint8_t scheme) const override {
    return scheme == 0x3Cu || scheme == 0x40u;
  }

  bool authenticationOnly(std::uint8_t scheme) const override {
    return scheme == 0x3Cu;
  }

  std::size_t authenticationTagLength(
      std::uint8_t scheme,
      std::uint8_t tagLengthCode) const override {
    if (tagLengthCode == 0u) {
      return 6u;
    }
    if (tagLengthCode == 1u) {
      return scheme == 0x40u ? 8u : 16u;
    }
    return tagLengthCode >= 4u ? static_cast<std::size_t>(tagLengthCode) * 2u : 0u;
  }

  std::size_t protectedPacketLength(
      std::uint8_t,
      std::size_t mqttSnPacketLength) const override {
    return mqttSnPacketLength;
  }

  mqttsn::ProtectedContent protect(
      const mqttsn::ProtectionContext& context,
      std::span<const std::uint8_t> mqttSnPacket) override {
    std::vector<std::uint8_t> protectedPacket(
        mqttSnPacket.begin(), mqttSnPacket.end());
    std::vector<std::uint8_t> tag(
        authenticationTagLength(context.scheme, context.tagLengthCode),
        static_cast<std::uint8_t>(context.authenticatedPrefix.size()));
    return mqttsn::ProtectedContent{
        std::move(protectedPacket),
        std::move(tag)};
  }

  std::vector<std::uint8_t> unprotect(
      const mqttsn::ProtectionContext& context,
      std::span<const std::uint8_t> protectedPacket,
      std::span<const std::uint8_t> authenticationTag) override {
    const auto expected =
        static_cast<std::uint8_t>(context.authenticatedPrefix.size());
    for (const auto value : authenticationTag) {
      if (value != expected) {
        throw std::runtime_error("authentication failed");
      }
    }
    return std::vector<std::uint8_t>(
        protectedPacket.begin(), protectedPacket.end());
  }
};

static void test_protection_wrapper() {
  CopyProtectionProvider provider;
  const std::array<std::uint8_t, 8> sender{
      1u,2u,3u,4u,5u,6u,7u,8u};
  const std::array<std::uint8_t, 4> random{
      9u,10u,11u,12u};
  const std::array<std::uint8_t, 2> crypto{
      0x21u,0x22u};
  const std::array<std::uint8_t, 2> counter{
      0x00u,0x01u};
  const std::array<std::uint8_t, 4> inner{
      0x04u,0x0Cu,0x12u,0x34u};

  const mqttsn::ProtectionEnvelope envelope{
      0x3Cu,
      0x04u,
      sender,
      random,
      crypto,
      counter,
      inner};

  auto encoded = mqttsn::ProtectionCodec::encode(envelope, provider);
  auto decoded = mqttsn::ProtectionCodec::decode(encoded, provider);

  assert(decoded.scheme == 0x3Cu);
  assert(decoded.tagLengthCode == 0x04u);
  assert(decoded.senderIdentifier.size() == 8u);
  assert(decoded.random.size() == 4u);
  assert(decoded.cryptographicMaterial.size() == 2u);
  assert(decoded.monotonicCounter.size() == 2u);
  assert(decoded.mqttSnPacket.size() == 4u);
  assert(decoded.mqttSnPacket[1] == 0x0Cu);

  encoded.back() ^= 0x01u;
  try {
    (void)mqttsn::ProtectionCodec::decode(encoded, provider);
    assert(false);
  } catch (const mqttsn::Error& error) {
    assert(error.status() == MQTTSN_MALFORMED_PACKET);
  }
}

int main() {
  test_short_and_extended_framing();
  test_connect_and_connack();
  test_connack_authentication_views();
  test_invalid_input_reports_native_status();
  test_connect_validation_is_delegated_to_c();
  test_all_packet_types_can_use_generic_framing();
  test_pubwos_and_gateway_discovery_wrappers();
  test_timer_wrappers();
  test_encapsulation_wrappers();
  test_session_wrapper();
  test_protection_wrapper();
  return 0;
}
