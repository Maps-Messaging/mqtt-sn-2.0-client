#ifndef MQTT_SN_2_MQTTSN_HPP
#define MQTT_SN_2_MQTTSN_HPP

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

extern "C" {
#include "mqttsn/mqttsn.h"
#include "mqttsn/packets.h"
#include "mqttsn/client.h"
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


struct PubWosPacket {
  bool retain{false};
  mqttsn_topic_type_t topicType{MQTTSN_TOPIC_NAME};
  std::uint16_t topicAlias{};
  std::string_view topicName{};
  std::span<const std::uint8_t> payload{};
};

struct AdvertisePacket {
  std::uint8_t gatewayIdentifier{};
  std::uint16_t durationSeconds{};
};

struct SearchGwPacket {
  std::span<const std::uint8_t> additionalNetworkInformation{};
};

struct GwInfoPacket {
  std::uint8_t gatewayIdentifier{};
  std::span<const std::uint8_t> gatewayAddress{};
};


enum class RetryAction {
  None = MQTTSN_RETRY_NONE,
  Retransmit = MQTTSN_RETRY_RETRANSMIT,
  DeleteConnection = MQTTSN_RETRY_DELETE_CONNECTION
};

class RetryTimer {
 public:
  RetryTimer(std::uint64_t retryIntervalMs, std::uint32_t maximumRetryCount) {
    mqttsn_retry_timer_init(&native_, retryIntervalMs, maximumRetryCount);
    if (retryIntervalMs == 0u) {
      throw std::invalid_argument("retryIntervalMs must be > 0");
    }
  }

  void start(std::uint64_t nowMs) { mqttsn_retry_timer_start(&native_, nowMs); }
  void cancel() { mqttsn_retry_timer_cancel(&native_); }
  [[nodiscard]] bool active() const noexcept { return native_.active != 0; }
  [[nodiscard]] std::uint32_t retriesSent() const noexcept { return native_.retries_sent; }

  RetryAction poll(std::uint64_t nowMs) {
    return static_cast<RetryAction>(mqttsn_retry_timer_poll(&native_, nowMs));
  }

 private:
  mqttsn_retry_timer_t native_{};
};

enum class KeepAliveAction {
  None = MQTTSN_KEEP_ALIVE_NONE,
  SendPingReq = MQTTSN_KEEP_ALIVE_SEND_PINGREQ
};

class KeepAliveTimer {
 public:
  explicit KeepAliveTimer(std::uint64_t keepAliveMs) {
    mqttsn_keep_alive_timer_init(&native_, keepAliveMs);
    if (keepAliveMs == 0u) {
      throw std::invalid_argument("keepAliveMs must be > 0");
    }
  }

  void start(std::uint64_t nowMs) { mqttsn_keep_alive_timer_start(&native_, nowMs); }
  void outboundActivity(std::uint64_t nowMs) {
    mqttsn_keep_alive_timer_outbound_activity(&native_, nowMs);
  }
  void stop() { mqttsn_keep_alive_timer_stop(&native_); }
  [[nodiscard]] bool active() const noexcept { return native_.active != 0; }

  KeepAliveAction poll(std::uint64_t nowMs) {
    return static_cast<KeepAliveAction>(
        mqttsn_keep_alive_timer_poll(&native_, nowMs));
  }

 private:
  mqttsn_keep_alive_timer_t native_{};
};

class Codec {
 public:


  static std::vector<std::uint8_t> encodePubWos(const PubWosPacket& packet) {
    mqttsn_pubwos_t native{};
    native.retain = static_cast<std::uint8_t>(packet.retain);
    native.topic.type = packet.topicType;
    native.topic.alias = packet.topicAlias;
    native.topic.name = reinterpret_cast<const std::uint8_t*>(packet.topicName.data());
    native.topic.name_length = packet.topicName.size();
    native.payload = packet.payload.data();
    native.payload_length = packet.payload.size();

    const std::size_t capacity =
        7u + packet.topicName.size() + packet.payload.size();
    std::vector<std::uint8_t> output(capacity);
    std::size_t written = 0;
    const auto status = mqttsn_encode_pubwos(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static PubWosPacket decodePubWos(const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_pubwos_t native{};
    const auto status = mqttsn_decode_pubwos(&nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return PubWosPacket{
        native.retain != 0,
        native.topic.type,
        native.topic.alias,
        std::string_view(
            reinterpret_cast<const char*>(native.topic.name),
            native.topic.name_length),
        std::span<const std::uint8_t>(native.payload, native.payload_length)};
  }

  static std::vector<std::uint8_t> encodeAdvertise(const AdvertisePacket& packet) {
    const mqttsn_advertise_t native{
        packet.gatewayIdentifier, packet.durationSeconds};
    std::vector<std::uint8_t> output(5u);
    std::size_t written = 0;
    const auto status = mqttsn_encode_advertise(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static AdvertisePacket decodeAdvertise(const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_advertise_t native{};
    const auto status = mqttsn_decode_advertise(&nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return AdvertisePacket{native.gateway_identifier, native.duration};
  }

  static std::vector<std::uint8_t> encodeSearchGw(const SearchGwPacket& packet) {
    const mqttsn_searchgw_t native{
        packet.additionalNetworkInformation.data(),
        packet.additionalNetworkInformation.size()};
    std::vector<std::uint8_t> output(4u + packet.additionalNetworkInformation.size());
    std::size_t written = 0;
    const auto status = mqttsn_encode_searchgw(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static SearchGwPacket decodeSearchGw(const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_searchgw_t native{};
    const auto status = mqttsn_decode_searchgw(&nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return SearchGwPacket{std::span<const std::uint8_t>(
        native.additional_network_information,
        native.additional_network_information_length)};
  }

  static std::vector<std::uint8_t> encodeGwInfo(const GwInfoPacket& packet) {
    const mqttsn_gwinfo_t native{
        packet.gatewayIdentifier,
        packet.gatewayAddress.data(),
        packet.gatewayAddress.size()};
    std::vector<std::uint8_t> output(5u + packet.gatewayAddress.size());
    std::size_t written = 0;
    const auto status = mqttsn_encode_gwinfo(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static GwInfoPacket decodeGwInfo(const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_gwinfo_t native{};
    const auto status = mqttsn_decode_gwinfo(&nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return GwInfoPacket{
        native.gateway_identifier,
        std::span<const std::uint8_t>(
            native.gateway_address, native.gateway_address_length)};
  }

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
