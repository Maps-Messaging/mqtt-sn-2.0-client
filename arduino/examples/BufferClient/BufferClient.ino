/*
 * MQTT-SN 2.0 transport-neutral Arduino example.
 *
 * The sketch intentionally does not include WiFiUDP, EthernetUDP, Serial,
 * LoRa, or another transport. Feed bytes received by your transport into
 * mqttsn_decode_packet()/mqttsn_process_input(), and send the bytes produced
 * by mqttsn_encode_packet() using that transport.
 */

extern "C" {
#include <mqttsn.h>
}

static uint8_t outbound[32];

static void transportSend(const uint8_t *data, size_t length) {
  // Replace with UDP/DTLS/Serial/LoRa/etc. The MQTT-SN core does not care.
  (void)data;
  (void)length;
}

static mqttsn_status_t onPacket(
    void *context,
    const mqttsn_packet_view_t *packet) {
  (void)context;
  // Application handling goes here.
  (void)packet;
  return MQTTSN_OK;
}

void setup() {
  size_t written = 0;

  // Example outbound PINGREQ. Section 2.1 framing is handled by the C core.
  if (mqttsn_encode_packet(
          MQTTSN_PINGREQ,
          nullptr,
          0,
          outbound,
          sizeof(outbound),
          &written) == MQTTSN_OK) {
    transportSend(outbound, written);
  }
}

void loop() {
  // Example for a transport receive callback:
  //
  // uint8_t inbound[256];
  // size_t received = transportReceive(inbound, sizeof(inbound));
  // size_t consumed = 0;
  // mqttsn_process_input(inbound, received, onPacket, nullptr, &consumed);
}
