import collections
import math
import time
from http import HTTPStatus
from threading import Lock

from fastapi import HTTPException, Request

from . import models


def _get_identifier(request: Request) -> str:
    """Generate a unique identifier for the request."""
    if forwarded := request.headers.get("x-forwarded-for"):
        return f"{forwarded.split(',')[0]}:{request.url.path}"
    return f"{request.client.host}:{request.url.path}"


class RateLimiter:
    """Rate limiter for incoming requests.

    >>> RateLimiter

    """

    def __init__(self, rps: models.RateLimit):
        # noinspection PyUnresolvedReferences
        """Instantiates the object with the necessary args.

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
        """Checks if the number of calls exceeds the rate limit for the given identifier.

        Args:
            request: The incoming request object.

        Raises:
            429: Too many requests.
        """
        identifier = _get_identifier(request)
        current_time = time.time()

        with self.locks[identifier]:
            # Clean up expired timestamps
            self.requests[identifier] = [
                timestamp
                for timestamp in self.requests[identifier]
                if current_time - timestamp < self.seconds
            ]

            if len(self.requests[identifier]) >= self.max_requests:
                raise HTTPException(
                    status_code=HTTPStatus.TOO_MANY_REQUESTS.value,
                    detail=HTTPStatus.TOO_MANY_REQUESTS.phrase,
                    headers={"Retry-After": str(math.ceil(self.seconds))},
                )
            self.requests[identifier].append(current_time)
