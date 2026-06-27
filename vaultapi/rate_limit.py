"""Rate limiter module that enforces per-client request limits using a sliding-window algorithm."""

import collections
import math
import time
from http import HTTPStatus
from threading import Lock

from fastapi import HTTPException, Request

from . import models


def _get_identifier(request: Request) -> str:
    """Build a unique string key for a request based on the client IP and path.

    Args:
        request: Incoming FastAPI request object.

    Returns:
        str:
        ``"<ip>:<path>"`` string, using the first IP from ``X-Forwarded-For`` when present.
    """
    if forwarded := request.headers.get("x-forwarded-for"):
        return f"{forwarded.split(',')[0]}:{request.url.path}"
    return f"{request.client.host}:{request.url.path}"


class RateLimiter:
    """Rate limiter for incoming requests.

    >>> RateLimiter

    """

    def __init__(self, rps: models.RateLimit):
        # noinspection PyUnresolvedReferences
        """Instantiate the rate limiter with the given rate limit configuration.

        Args:
            rps: RateLimit object with ``max_requests`` and ``seconds``.

        Attributes:
            max_requests: Maximum requests to allow in a given time frame.
            seconds: Number of seconds after which the cache is set to expire.
        """
        self.max_requests = rps.max_requests
        self.seconds = rps.seconds
        self.locks = collections.defaultdict(Lock)  # For thread-safe access
        self.requests = collections.defaultdict(list)

    def init(self, request: Request) -> None:
        """Check whether the request exceeds the rate limit for its identifier.

        Args:
            request: Incoming FastAPI request object.

        Raises:
            HTTPException:
            - 429: Too many requests within the configured window.
        """
        identifier = _get_identifier(request)
        current_time = time.time()

        with self.locks[identifier]:
            # Clean up expired timestamps
            self.requests[identifier] = [
                timestamp for timestamp in self.requests[identifier] if current_time - timestamp < self.seconds
            ]

            if len(self.requests[identifier]) >= self.max_requests:
                raise HTTPException(
                    status_code=HTTPStatus.TOO_MANY_REQUESTS.value,
                    detail=HTTPStatus.TOO_MANY_REQUESTS.phrase,
                    headers={"Retry-After": str(math.ceil(self.seconds))},
                )
            self.requests[identifier].append(current_time)
