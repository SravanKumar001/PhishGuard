from collections import OrderedDict, deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(
        self,
        max_requests: int,
        window_seconds: int = 60,
        max_clients: int = 2048,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._requests: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = Lock()

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()

    def check(self, key: str) -> None:
        now = monotonic()
        with self._lock:
            requests = self._requests.get(key, deque())
            requests = deque(
                timestamp
                for timestamp in requests
                if now - timestamp < self.window_seconds
            )
            if len(requests) >= self.max_requests:
                retry_after = max(1, int(self.window_seconds - (now - requests[0])))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many authentication attempts. Try again later.",
                    headers={"Retry-After": str(retry_after)},
                )
            if key not in self._requests and len(self._requests) >= self.max_clients:
                self._requests.popitem(last=False)
            requests.append(now)
            self._requests[key] = requests
            self._requests.move_to_end(key)


def rate_limit_key(request: Request, action: str) -> str:
    client_host = request.client.host if request.client else "unknown"
    return f"{action}:{client_host}"
