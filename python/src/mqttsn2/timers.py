from dataclasses import dataclass
from enum import Enum, auto


class RetryAction(Enum):
    NONE = auto()
    RETRANSMIT = auto()
    DELETE_CONNECTION = auto()


@dataclass
class RetryTimer:
    retry_interval_ms: int
    maximum_retry_count: int
    active: bool = False
    retries_sent: int = 0
    deadline_ms: int = 0

    def __post_init__(self) -> None:
        if self.retry_interval_ms <= 0:
            raise ValueError("retry_interval_ms must be > 0")
        if self.maximum_retry_count < 0:
            raise ValueError("maximum_retry_count must be >= 0")

    def start(self, now_ms: int) -> None:
        self.active = True
        self.retries_sent = 0
        self.deadline_ms = now_ms + self.retry_interval_ms

    def cancel(self) -> None:
        self.active = False
        self.retries_sent = 0

    def poll(self, now_ms: int) -> RetryAction:
        if not self.active or now_ms < self.deadline_ms:
            return RetryAction.NONE

        if self.retries_sent < self.maximum_retry_count:
            self.retries_sent += 1
            self.deadline_ms = now_ms + self.retry_interval_ms
            return RetryAction.RETRANSMIT

        self.active = False
        return RetryAction.DELETE_CONNECTION


class KeepAliveAction(Enum):
    NONE = auto()
    SEND_PINGREQ = auto()


@dataclass
class KeepAliveTimer:
    keep_alive_ms: int
    active: bool = False
    deadline_ms: int = 0

    def __post_init__(self) -> None:
        if self.keep_alive_ms <= 0:
            raise ValueError("keep_alive_ms must be > 0")

    def start(self, now_ms: int) -> None:
        self.active = True
        self.deadline_ms = now_ms + self.keep_alive_ms

    def outbound_activity(self, now_ms: int) -> None:
        if self.active:
            self.deadline_ms = now_ms + self.keep_alive_ms

    def stop(self) -> None:
        self.active = False

    def poll(self, now_ms: int) -> KeepAliveAction:
        if not self.active or now_ms < self.deadline_ms:
            return KeepAliveAction.NONE

        self.deadline_ms = now_ms + self.keep_alive_ms
        return KeepAliveAction.SEND_PINGREQ
