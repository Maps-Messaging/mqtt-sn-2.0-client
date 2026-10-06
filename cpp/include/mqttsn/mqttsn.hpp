#ifndef MQTT_SN_2_MQTTSN_HPP
#define MQTT_SN_2_MQTTSN_HPP

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

extern "C" {
#include "mqttsn/mqttsn.h"
}

namespace mqttsn {

enum class PacketType : std::uint8_t {
  Connect = MQTTSN_CONNECT,
  ConnAck = MQTTSN_CONNACK,
  Publish = MQTTSN_PUBLISH,
  PubAck = MQTTSN_PUBACK,
  PubRec = MQTTSN_PUBREC,
  PubRel = MQTTSN_PUBREL,
  PubComp = MQTTSN_PUBCOMP,
  Subscribe = MQTTSN_SUBSCRIBE,
  SubAck = MQTTSN_SUBACK,
  Unsubscribe = MQTTSN_UNSUBSCRIBE,
  UnsubAck = MQTTSN_UNSUBACK,
  PingReq = MQTTSN_PINGREQ,
  PingResp = MQTTSN_PINGRESP,
  Disconnect = MQTTSN_DISCONNECT,
  Auth = MQTTSN_AUTH,
  Register = MQTTSN_REGISTER,
  RegAck = MQTTSN_REGACK,
  PubWos = MQTTSN_PUBWOS,
  SleepReq = MQTTSN_SLEEPREQ,
  SleepResp = MQTTSN_SLEEPRESP,
  Wakeup = MQTTSN_WAKEUP,
  Advertise = MQTTSN_ADVERTISE,
  SearchGw = MQTTSN_SEARCHGW,
  GwInfo = MQTTSN_GWINFO,
  ForwarderEncapsulation = MQTTSN_FORWARDER_ENCAPSULATION,
  ConnectionEncapsulation = MQTTSN_CONNECTION_ENCAPSULATION,
  ProtectionEncapsulation = MQTTSN_PROTECTION_ENCAPSULATION
};

class Error : public std::runtime_error {
 public:
  explicit Error(mqttsn_status_t status)
      : std::runtime_error("MQTT-SN codec error"), status_(status) {}

  [[nodiscard]] mqttsn_status_t status() const noexcept { return status_; }

 private:
  mqttsn_status_t status_;
};

struct PacketView {
  PacketType type;
  std::span<const std::uint8_t> body;
  std::size_t packetLength;
  std::size_t headerLength;
};


struct ConnectOptions {
  bool cleanStart{true};
  bool allowNetworkAddressChanges{false};
  bool allowServerSuggestedValues{false};
  std::uint16_t packetIdentifier{};
  std::uint16_t keepAliveSeconds{};
  std::uint16_t maximumPacketSize{};
  std::string_view clientIdentifier{};
};

struct ConnAckView {
  bool sessionPresent;
  std::uint16_t packetIdentifier;
  std::uint8_t reasonCode;
  bool hasSessionExpiryInterval;
  std::uint32_t sessionExpiryInterval;
  bool hasServerKeepAlive;
  std::uint16_t serverKeepAlive;
  bool hasAuthentication;
  std::string_view authenticationMethod;
  std::span<const std::uint8_t> authenticationData;
  std::string_view assignedClientIdentifier;
};

class Codec {
 public:

  static std::vector<std::uint8_t> encodeConnect(const ConnectOptions& options) {
    const mqttsn_connect_options_t native{
        static_cast<std::uint8_t>(options.cleanStart),
        static_cast<std::uint8_t>(options.allowNetworkAddressChanges),
        static_cast<std::uint8_t>(options.allowServerSuggestedValues),
        options.packetIdentifier,
        options.keepAliveSeconds,
        options.maximumPacketSize,
        reinterpret_cast<const std::uint8_t*>(options.clientIdentifier.data()),
        options.clientIdentifier.size()};

    const std::size_t bodyLength = 8u + options.clientIdentifier.size();
    const std::size_t capacity = bodyLength <= 253u
        ? bodyLength + 2u
        : bodyLength + 4u;
    std::vector<std::uint8_t> output(capacity);
    std::size_t written = 0;
    const auto status = mqttsn_encode_connect(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static ConnAckView decodeConnAck(const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_connack_view_t native{};
    const auto status = mqttsn_decode_connack(&nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }

    return ConnAckView{
        native.session_present != 0,
        native.packet_identifier,
        native.reason_code,
        native.has_session_expiry_interval != 0,
        native.session_expiry_interval,
        native.has_server_keep_alive != 0,
        native.server_keep_alive,
        native.has_authentication != 0,
        std::string_view(
            reinterpret_cast<const char*>(native.authentication_method),
            native.authentication_method_length),
        std::span<const std::uint8_t>(
            native.authentication_data,
            native.authentication_data_length),
        std::string_view(
            reinterpret_cast<const char*>(native.assigned_client_identifier),
            native.assigned_client_identifier_length)};
  }

  static PacketView decode(std::span<const std::uint8_t> input) {
    mqttsn_packet_view_t native{};
    std::size_t consumed = 0;
    const auto status = mqttsn_decode_packet(
        input.data(), input.size(), &native, &consumed);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return PacketView{
        static_cast<PacketType>(native.type),
        std::span<const std::uint8_t>(native.body, native.body_length),
        native.packet_length,
        native.header_length};
  }

  static std::vector<std::uint8_t> encode(
      PacketType type,
      std::span<const std::uint8_t> body = {}) {
    const std::size_t capacity = body.size() <= 253u
        ? body.size() + 2u
        : body.size() + 4u;
    std::vector<std::uint8_t> output(capacity);
    std::size_t written = 0;
    const auto status = mqttsn_encode_packet(
        static_cast<mqttsn_packet_type_t>(type),
        body.data(),
        body.size(),
        output.data(),
        output.size(),
        &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }
};

}  // namespace mqttsn

#endif
