#
#  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
#
#  Licensed under the Apache License, Version 2.0 with the Commons Clause
#  (the "License"); you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
#
#      http://www.apache.org/licenses/LICENSE-2.0
#      https://commonsclause.com/
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

"""MQTT-SN 2.0 CSD01 §4.4.2 and §3.1.6 timer conformance tests.

Covers MQTT-SN-4.4.2-1/-2/-5/-7 and MQTT-SN-3.1.6-1/-3.
"""

from mqttsn2 import (
    KeepAliveAction,
    KeepAliveTimer,
    RetryAction,
    RetryTimer,
)


def test_retry_timer_retransmits_then_deletes_connection() -> None:
    timer = RetryTimer(1000, 2)
    timer.start(100)

    assert timer.poll(1099) is RetryAction.NONE
    assert timer.poll(1100) is RetryAction.RETRANSMIT
    assert timer.retries_sent == 1
    assert timer.poll(2100) is RetryAction.RETRANSMIT
    assert timer.retries_sent == 2
    assert timer.poll(3100) is RetryAction.DELETE_CONNECTION
    assert not timer.active


def test_keep_alive_timer_tracks_outbound_activity() -> None:
    timer = KeepAliveTimer(1000)
    timer.start(0)

    assert timer.poll(999) is KeepAliveAction.NONE
    timer.outbound_activity(900)
    assert timer.poll(1000) is KeepAliveAction.NONE
    assert timer.poll(1900) is KeepAliveAction.SEND_PINGREQ
