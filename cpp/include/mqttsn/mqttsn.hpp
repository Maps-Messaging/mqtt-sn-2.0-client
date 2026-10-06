#ifndef MQTT_SN_2_MQTTSN_HPP
#define MQTT_SN_2_MQTTSN_HPP

#include <cstdint>
#include <span>
#include <stdexcept>
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

class Codec {
 public:
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
