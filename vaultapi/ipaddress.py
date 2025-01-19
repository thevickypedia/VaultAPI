import re
import socket

import requests

# noinspection LongLine
IP_REGEX = re.compile(
    r"""^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$"""  # noqa: E501
)


def private() -> str | None:
    """Get private IP address of the host using socket connection.

    See Also:
        Uses Google's DNS endpoint to resolve the private IP address.

    References:
        https://dns.google/query?name=8.8.8.8

    Returns:
        str:
        Private IP address.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_:
        try:
            socket_.connect(("8.8.8.8", 80))
        except OSError:
            return
        ip_address_ = socket_.getsockname()[0]
    return ip_address_


def public() -> str | None:
    """Gets public IP address of the host using different endpoints.

    See Also:
        Uses 6 public IP retriever endpoints to get the public IP address.

    Returns:
        str:
        Public IP address.
    """
    fn1 = lambda fa: fa.text.strip()  # noqa: E731
    fn2 = lambda fa: fa.json()["origin"].strip()  # noqa: E731
    mapping = {
        "https://checkip.amazonaws.com/": fn1,
        "https://api.ipify.org/": fn1,
        "https://ipinfo.io/ip/": fn1,
        "https://v4.ident.me/": fn1,
        "https://httpbin.org/ip": fn2,
        "https://myip.dnsomatic.com/": fn1,
    }
    for url, func in mapping.items():
        try:
            with requests.get(url) as response:
                return IP_REGEX.findall(func(response))[0]
        except (
            requests.RequestException,
            requests.JSONDecodeError,
            re.error,
            IndexError,
        ):
            continue
