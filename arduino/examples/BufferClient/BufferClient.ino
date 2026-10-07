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
