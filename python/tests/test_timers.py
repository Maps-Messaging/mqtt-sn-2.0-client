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
