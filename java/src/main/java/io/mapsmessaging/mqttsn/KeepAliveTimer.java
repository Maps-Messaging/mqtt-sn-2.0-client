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

package io.mapsmessaging.mqttsn;

/**
 * Caller-clock-driven client Keep Alive helper.
 *
 * <p>Any outbound MQTT-SN Control Packet resets the timer. If no packet has
 * been sent for the Keep Alive interval, the caller should send PINGREQ.</p>
 */
public final class KeepAliveTimer {
  private final long keepAliveMillis;
  private boolean active;
  private long deadlineMillis;

  public KeepAliveTimer(long keepAliveMillis) {
    if (keepAliveMillis <= 0) {
      throw new IllegalArgumentException("keepAliveMillis must be > 0");
    }
    this.keepAliveMillis = keepAliveMillis;
  }

  public void start(long nowMillis) {
    active = true;
    deadlineMillis = Math.addExact(nowMillis, keepAliveMillis);
  }

  public void outboundActivity(long nowMillis) {
    if (active) {
      deadlineMillis = Math.addExact(nowMillis, keepAliveMillis);
    }
  }

  public void stop() {
    active = false;
  }

  public boolean active() {
    return active;
  }

  public KeepAliveAction poll(long nowMillis) {
    if (!active || nowMillis < deadlineMillis) {
      return KeepAliveAction.NONE;
    }
    deadlineMillis = Math.addExact(nowMillis, keepAliveMillis);
    return KeepAliveAction.SEND_PINGREQ;
  }
}
