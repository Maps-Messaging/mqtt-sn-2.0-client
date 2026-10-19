# MQTT-SN 2.0 sleep renewal

Tracking: MSG-325. Baseline: MQTT-SN 2.0 CSD01, 14 August 2026, OASIS commit
`0dae5066d123d068ddca2ddb861ce8858aafee92`.

A client may send another SLEEPREQ while already ASLEEP. This changes the sleep
configuration without a PINGREQ, an AWAKE transition, or a new CONNECT. The server
must acknowledge the request and restart its sleep cycle with the accepted
duration (MQTT-SN-3.15.5-7). A lost SLEEPRESP can be handled by retransmitting the
same SLEEPREQ with the same identifier; AUTH, by contrast, must never be retried.

Java, Python and C session controllers accept sleep renewal, correlate responses,
and remain ASLEEP after success. An outstanding request still prevents a second
different request. If SLEEPRESP supplies a duration, use it instead of the
requested duration. A rejected renewal retains the previous sleep configuration.
The accepted duration is available as Java `sleepDurationSeconds()`, Python
`sleep_duration_seconds`, C++ `sleepDurationSeconds()`, and C `sleep_duration`; timers remain caller-driven.
C++ and Arduino inherit the C controller behaviour. Rebuild C/C++ consumers
against the headers because the public client struct has grown.

Retain Topic Aliases applies to each request. Clearing session aliases must not
clear predefined aliases. Subscriptions and queued QoS 1/2 messages survive a
successful renewal. A PINGREQ subsequently wakes the client, buffered messages
complete their QoS exchanges, and PINGRESP returns it to ASLEEP. The server must
restart the sleep timer after writing PINGRESP, including empty wake cycles
(MQTT-SN-4.14.2-7).

## Validation — 19 October 2026

- Maven `test`/`install`: 120 core Java tests and 32 protection-provider tests passed.
- `PYTHONPATH=python/src python -m pytest python/tests -q`: 115 passed.
- C/C++ CMake build and CTest: all 7 executables passed, including OpenSSL tests.
- Arduino forwarding sources compiled with GCC against the canonical C auth and
  session test programs; both passed. No on-device Arduino test is claimed.
- The authentication-only commit was also checked independently: Java Maven,
  113 Python tests and all 7 C/C++ executables passed before adding sleep renewal.
