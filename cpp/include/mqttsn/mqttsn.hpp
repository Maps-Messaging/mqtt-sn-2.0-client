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
#include "mqttsn/protection.h"
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




struct AuthPacket {
  std::uint16_t packetIdentifier{};
  std::uint8_t reasonCode{};
  std::string_view authenticationMethod{};
  std::span<const std::uint8_t> authenticationData{};
};

struct DisconnectPacket {
  bool hasPacketIdentifier{false};
  std::uint16_t packetIdentifier{};
  bool hasReasonCode{false};
  std::uint8_t reasonCode{};
  bool hasSessionExpiryInterval{false};
  std::uint32_t sessionExpiryInterval{};
  std::string_view reasonString{};
};

struct ConnectionEncapsulation {
  std::string_view clientIdentifier{};
  std::span<const std::uint8_t> mqttSnPacket{};
};

struct ForwarderEncapsulation {
  std::span<const std::uint8_t> clientAddressingInformation{};
  std::span<const std::uint8_t> mqttSnPacket{};
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




struct ProtectionContext {
  std::uint8_t scheme{};
  std::uint8_t tagLengthCode{};
  std::span<const std::uint8_t> senderIdentifier{};
  std::span<const std::uint8_t> random{};
  std::span<const std::uint8_t> cryptographicMaterial{};
  std::span<const std::uint8_t> monotonicCounter{};
  std::span<const std::uint8_t> authenticatedPrefix{};
};

struct ProtectedContent {
  std::vector<std::uint8_t> protectedPacket;
  std::vector<std::uint8_t> authenticationTag;
};

class ProtectionProvider {
 public:
  virtual ~ProtectionProvider() = default;

  virtual bool supports(std::uint8_t scheme) const = 0;
  virtual bool authenticationOnly(std::uint8_t scheme) const = 0;
  virtual std::size_t authenticationTagLength(
      std::uint8_t scheme,
      std::uint8_t tagLengthCode) const = 0;
  virtual std::size_t protectedPacketLength(
      std::uint8_t scheme,
      std::size_t mqttSnPacketLength) const = 0;

  virtual ProtectedContent protect(
      const ProtectionContext& context,
      std::span<const std::uint8_t> mqttSnPacket) = 0;

  virtual std::vector<std::uint8_t> unprotect(
      const ProtectionContext& context,
      std::span<const std::uint8_t> protectedPacket,
      std::span<const std::uint8_t> authenticationTag) = 0;
};

struct ProtectionEnvelope {
  std::uint8_t scheme{};
  std::uint8_t tagLengthCode{};
  std::span<const std::uint8_t> senderIdentifier{};
  std::span<const std::uint8_t> random{};
  std::span<const std::uint8_t> cryptographicMaterial{};
  std::span<const std::uint8_t> monotonicCounter{};
  std::span<const std::uint8_t> mqttSnPacket{};
};

struct DecodedProtectionEnvelope {
  std::uint8_t scheme{};
  std::uint8_t tagLengthCode{};
  std::vector<std::uint8_t> senderIdentifier;
  std::vector<std::uint8_t> random;
  std::vector<std::uint8_t> cryptographicMaterial;
  std::vector<std::uint8_t> monotonicCounter;
  std::vector<std::uint8_t> mqttSnPacket;
};

enum class ClientState {
  None = MQTTSN_CLIENT_NONE,
  Disconnected = MQTTSN_CLIENT_DISCONNECTED,
  Connecting = MQTTSN_CLIENT_CONNECTING,
  Active = MQTTSN_CLIENT_ACTIVE,
  Asleep = MQTTSN_CLIENT_ASLEEP,
  Awake = MQTTSN_CLIENT_AWAKE
};


class ProtectionCodec {
 public:
  static std::vector<std::uint8_t> encode(
      const ProtectionEnvelope& envelope,
      ProtectionProvider& provider) {
    ProviderBridge bridge(provider);
    const mqttsn_protection_provider_t nativeProvider = bridge.native();

    const mqttsn_protection_envelope_t nativeEnvelope{
        envelope.scheme,
        envelope.tagLengthCode,
        envelope.senderIdentifier.data(),
        envelope.senderIdentifier.size(),
        envelope.random.data(),
        envelope.random.size(),
        envelope.cryptographicMaterial.data(),
        envelope.cryptographicMaterial.size(),
        envelope.monotonicCounter.data(),
        envelope.monotonicCounter.size(),
        envelope.mqttSnPacket.data(),
        envelope.mqttSnPacket.size()};

    std::vector<std::uint8_t> output(MQTTSN_MAX_PACKET_SIZE);
    std::size_t written = 0;
    const auto status = mqttsn_encode_protection(
        &nativeEnvelope,
        &nativeProvider,
        output.data(),
        output.size(),
        &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static DecodedProtectionEnvelope decode(
      std::span<const std::uint8_t> encoded,
      ProtectionProvider& provider) {
    ProviderBridge bridge(provider);
    const mqttsn_protection_provider_t nativeProvider = bridge.native();

    std::vector<std::uint8_t> inner(MQTTSN_MAX_PACKET_SIZE);
    std::size_t innerWritten = 0;
    mqttsn_protection_envelope_t nativeEnvelope{};

    const auto status = mqttsn_decode_protection(
        encoded.data(),
        encoded.size(),
        &nativeProvider,
        inner.data(),
        inner.size(),
        &innerWritten,
        &nativeEnvelope);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }

    inner.resize(innerWritten);
    return DecodedProtectionEnvelope{
        nativeEnvelope.scheme,
        nativeEnvelope.tag_length_code,
        std::vector<std::uint8_t>(
            nativeEnvelope.sender_identifier,
            nativeEnvelope.sender_identifier + nativeEnvelope.sender_identifier_length),
        std::vector<std::uint8_t>(
            nativeEnvelope.random,
            nativeEnvelope.random + nativeEnvelope.random_length),
        std::vector<std::uint8_t>(
            nativeEnvelope.cryptographic_material,
            nativeEnvelope.cryptographic_material
                + nativeEnvelope.cryptographic_material_length),
        std::vector<std::uint8_t>(
            nativeEnvelope.monotonic_counter,
            nativeEnvelope.monotonic_counter + nativeEnvelope.monotonic_counter_length),
        std::move(inner)};
  }

 private:
  class ProviderBridge {
   public:
    explicit ProviderBridge(ProtectionProvider& provider) : provider_(provider) {}

    mqttsn_protection_provider_t native() {
      mqttsn_protection_provider_t result{};
      result.user_data = this;
      result.supports = &supports;
      result.authentication_only = &authenticationOnly;
      result.authentication_tag_length = &authenticationTagLength;
      result.protected_packet_length = &protectedPacketLength;
      result.protect = &protect;
      result.unprotect = &unprotect;
      return result;
    }

   private:
    static ProviderBridge& self(void* userData) {
      return *static_cast<ProviderBridge*>(userData);
    }

    static int supports(void* userData, std::uint8_t scheme) {
      return self(userData).provider_.supports(scheme) ? 1 : 0;
    }

    static int authenticationOnly(void* userData, std::uint8_t scheme) {
      return self(userData).provider_.authenticationOnly(scheme) ? 1 : 0;
    }

    static std::size_t authenticationTagLength(
        void* userData,
        std::uint8_t scheme,
        std::uint8_t tagLengthCode) {
      return self(userData).provider_.authenticationTagLength(
          scheme, tagLengthCode);
    }

    static std::size_t protectedPacketLength(
        void* userData,
        std::uint8_t scheme,
        std::size_t mqttSnPacketLength) {
      return self(userData).provider_.protectedPacketLength(
          scheme, mqttSnPacketLength);
    }

    static mqttsn_status_t protect(
        void* userData,
        const mqttsn_protection_context_t* context,
        const std::uint8_t* mqttSnPacket,
        std::size_t mqttSnPacketLength,
        std::uint8_t* protectedPacket,
        std::size_t protectedPacketCapacity,
        std::size_t* protectedPacketWritten,
        std::uint8_t* authenticationTag,
        std::size_t authenticationTagCapacity,
        std::size_t* authenticationTagWritten) {
      try {
        const ProtectionContext cppContext = toCpp(*context);
        const ProtectedContent content = self(userData).provider_.protect(
            cppContext,
            std::span<const std::uint8_t>(mqttSnPacket, mqttSnPacketLength));

        if (content.protectedPacket.size() > protectedPacketCapacity ||
            content.authenticationTag.size() > authenticationTagCapacity) {
          return MQTTSN_BUFFER_TOO_SMALL;
        }

        std::copy(
            content.protectedPacket.begin(),
            content.protectedPacket.end(),
            protectedPacket);
        std::copy(
            content.authenticationTag.begin(),
            content.authenticationTag.end(),
            authenticationTag);

        *protectedPacketWritten = content.protectedPacket.size();
        *authenticationTagWritten = content.authenticationTag.size();
        return MQTTSN_OK;
      } catch (...) {
        return MQTTSN_MALFORMED_PACKET;
      }
    }

    static mqttsn_status_t unprotect(
        void* userData,
        const mqttsn_protection_context_t* context,
        const std::uint8_t* protectedPacket,
        std::size_t protectedPacketLength,
        const std::uint8_t* authenticationTag,
        std::size_t authenticationTagLength,
        std::uint8_t* mqttSnPacket,
        std::size_t mqttSnPacketCapacity,
        std::size_t* mqttSnPacketWritten) {
      try {
        const ProtectionContext cppContext = toCpp(*context);
        const auto plain = self(userData).provider_.unprotect(
            cppContext,
            std::span<const std::uint8_t>(
                protectedPacket, protectedPacketLength),
            std::span<const std::uint8_t>(
                authenticationTag, authenticationTagLength));

        if (plain.size() > mqttSnPacketCapacity) {
          return MQTTSN_BUFFER_TOO_SMALL;
        }
        std::copy(plain.begin(), plain.end(), mqttSnPacket);
        *mqttSnPacketWritten = plain.size();
        return MQTTSN_OK;
      } catch (...) {
        return MQTTSN_MALFORMED_PACKET;
      }
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

    ProtectionProvider& provider_;
  };
};

class Session {
 public:
  explicit Session(std::uint16_t initialPacketIdentifier = 1u) {
    mqttsn_client_init(&native_, initialPacketIdentifier);
  }

  [[nodiscard]] ClientState state() const noexcept {
    return static_cast<ClientState>(native_.state);
  }

  [[nodiscard]] bool hasOutboundRequest() const noexcept {
    return native_.has_outbound_request != 0;
  }

  [[nodiscard]] bool hasInboundRequest() const noexcept {
    return native_.has_inbound_request != 0;
  }

  [[nodiscard]] std::uint16_t outboundPacketIdentifier() const noexcept {
    return native_.outbound_packet_identifier;
  }

  [[nodiscard]] std::uint16_t inboundPacketIdentifier() const noexcept {
    return native_.inbound_packet_identifier;
  }

  std::uint16_t nextPacketIdentifier() {
    return mqttsn_client_next_packet_identifier(&native_);
  }

  [[nodiscard]] bool canSend(PacketType type) const {
    return mqttsn_client_can_send(
        &native_, static_cast<mqttsn_packet_type_t>(type)) != 0;
  }

  void trackOutbound(std::span<const std::uint8_t> packet) {
    const auto status = mqttsn_client_track_outbound(
        &native_, packet.data(), packet.size());
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
  }

  void trackInbound(std::span<const std::uint8_t> packet) {
    const auto status = mqttsn_client_track_inbound(
        &native_, packet.data(), packet.size());
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
  }

  void retryExhausted() {
    mqttsn_client_retry_exhausted(&native_);
  }

 private:
  mqttsn_client_t native_{};
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




  static std::vector<std::uint8_t> encodeAuth(const AuthPacket& packet) {
    const mqttsn_auth_t native{
        packet.packetIdentifier,
        packet.reasonCode,
        reinterpret_cast<const std::uint8_t*>(packet.authenticationMethod.data()),
        packet.authenticationMethod.size(),
        packet.authenticationData.data(),
        packet.authenticationData.size()};
    std::vector<std::uint8_t> output(
        8u + packet.authenticationMethod.size() + packet.authenticationData.size());
    std::size_t written = 0;
    const auto status = mqttsn_encode_auth(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static AuthPacket decodeAuth(const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_auth_t native{};
    const auto status = mqttsn_decode_auth(&nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return AuthPacket{
        native.packet_identifier,
        native.reason_code,
        std::string_view(
            reinterpret_cast<const char*>(native.authentication_method),
            native.authentication_method_length),
        std::span<const std::uint8_t>(
            native.authentication_data, native.authentication_data_length)};
  }

  static std::vector<std::uint8_t> encodeDisconnect(
      const DisconnectPacket& packet) {
    const mqttsn_disconnect_options_t native{
        static_cast<std::uint8_t>(packet.hasPacketIdentifier),
        packet.packetIdentifier,
        static_cast<std::uint8_t>(packet.hasReasonCode),
        packet.reasonCode,
        static_cast<std::uint8_t>(packet.hasSessionExpiryInterval),
        packet.sessionExpiryInterval,
        reinterpret_cast<const std::uint8_t*>(packet.reasonString.data()),
        packet.reasonString.size()};
    std::vector<std::uint8_t> output(12u + packet.reasonString.size());
    std::size_t written = 0;
    const auto status = mqttsn_encode_disconnect(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static DisconnectPacket decodeDisconnect(const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_disconnect_view_t native{};
    const auto status = mqttsn_decode_disconnect(&nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return DisconnectPacket{
        native.has_packet_identifier != 0,
        native.packet_identifier,
        native.has_reason_code != 0,
        native.reason_code,
        native.has_session_expiry_interval != 0,
        native.session_expiry_interval,
        std::string_view(
            reinterpret_cast<const char*>(native.reason_string),
            native.reason_string_length)};
  }

  static std::vector<std::uint8_t> encodeConnectionEncapsulation(
      const ConnectionEncapsulation& encapsulation) {
    const mqttsn_connection_encapsulation_t native{
        reinterpret_cast<const std::uint8_t*>(encapsulation.clientIdentifier.data()),
        encapsulation.clientIdentifier.size(),
        encapsulation.mqttSnPacket.data(),
        encapsulation.mqttSnPacket.size()};
    std::vector<std::uint8_t> output(
        8u + encapsulation.clientIdentifier.size() + encapsulation.mqttSnPacket.size());
    std::size_t written = 0;
    const auto status = mqttsn_encode_connection_encapsulation(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static ConnectionEncapsulation decodeConnectionEncapsulation(
      const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_connection_encapsulation_t native{};
    const auto status = mqttsn_decode_connection_encapsulation(
        &nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return ConnectionEncapsulation{
        std::string_view(
            reinterpret_cast<const char*>(native.client_identifier),
            native.client_identifier_length),
        std::span<const std::uint8_t>(
            native.mqttsn_packet, native.mqttsn_packet_length)};
  }

  static std::vector<std::uint8_t> encodeForwarderEncapsulation(
      const ForwarderEncapsulation& encapsulation) {
    const mqttsn_forwarder_encapsulation_t native{
        encapsulation.clientAddressingInformation.data(),
        encapsulation.clientAddressingInformation.size(),
        encapsulation.mqttSnPacket.data(),
        encapsulation.mqttSnPacket.size()};
    std::vector<std::uint8_t> output(
        7u + encapsulation.clientAddressingInformation.size()
        + encapsulation.mqttSnPacket.size());
    std::size_t written = 0;
    const auto status = mqttsn_encode_forwarder_encapsulation(
        &native, output.data(), output.size(), &written);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    output.resize(written);
    return output;
  }

  static ForwarderEncapsulation decodeForwarderEncapsulation(
      const PacketView& packet) {
    const mqttsn_packet_view_t nativePacket{
        static_cast<mqttsn_packet_type_t>(packet.type),
        packet.body.data(),
        packet.body.size(),
        packet.packetLength,
        packet.headerLength};
    mqttsn_forwarder_encapsulation_t native{};
    const auto status = mqttsn_decode_forwarder_encapsulation(
        &nativePacket, &native);
    if (status != MQTTSN_OK) {
      throw Error(status);
    }
    return ForwarderEncapsulation{
        std::span<const std::uint8_t>(
            native.client_addressing_information,
            native.client_addressing_information_length),
        std::span<const std::uint8_t>(
            native.mqttsn_packet, native.mqttsn_packet_length)};
  }

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
