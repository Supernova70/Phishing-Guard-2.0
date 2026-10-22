"""Safe fetch: SSRF, redirects, limits, and header isolation."""

from __future__ import annotations

import socket

import httpx
import pytest

from app.security.safe_fetch import SafeFetchError, SafeFetcher
from app.security.url_safety import UrlSafetyValidator


def answer(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


def resolver_for(*ips: str):
    def resolve(*_args, **_kwargs):
        return [answer(ip) for ip in ips]

    return resolve


def make_fetcher(handler, *, ips=("93.184.216.34",), **kwargs):
    client = lambda: httpx.Client(  # noqa: E731
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    return SafeFetcher(
        validator=UrlSafetyValidator(resolver=resolver_for(*ips)),
        client_factory=client,
        **kwargs,
    )


def test_fetches_public_body_and_headers():
    def handler(request):
        return httpx.Response(
            200,
            content=b"hello",
            headers={"content-type": "text/plain"},
            request=request,
        )

    result = make_fetcher(handler).fetch("https://public.test/a")
    assert result.status_code == 200
    assert result.body == b"hello"
    assert result.content_type == "text/plain"
    assert result.final_url == "https://public.test/a"
    assert result.redirects == ()


def test_private_literal_is_blocked_before_handler():
    called = []

    def handler(request):
        called.append(request)
        return httpx.Response(200, content=b"nope", request=request)

    fetcher = make_fetcher(handler, ips=("93.184.216.34",))
    with pytest.raises(SafeFetchError) as exc:
        fetcher.fetch("http://169.254.169.254/latest/meta-data/")
    assert exc.value.code == "unsafe_url"
    assert called == []


def test_redirect_to_private_destination_is_blocked():
    def handler(request):
        return httpx.Response(
            302,
            headers={"location": "http://169.254.169.254/secret"},
            request=request,
        )

    with pytest.raises(SafeFetchError) as exc:
        make_fetcher(handler).fetch("https://public.test/")
    assert exc.value.code == "unsafe_url"


def test_redirect_limit_is_enforced():
    def handler(request):
        return httpx.Response(
            302,
            headers={"location": "/again"},
            request=request,
        )

    with pytest.raises(SafeFetchError) as exc:
        make_fetcher(handler, max_redirects=1).fetch("https://public.test/start")
    assert exc.value.code == "too_many_redirects"


def test_redirect_chain_is_recorded():
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(
                301, headers={"location": "/final"}, request=request
            )
        return httpx.Response(200, content=b"ok", request=request)

    result = make_fetcher(handler).fetch("https://public.test/start")
    assert result.final_url == "https://public.test/final"
    assert result.redirects == ("https://public.test/final",)


def test_streamed_body_limit_is_enforced():
    def handler(request):
        return httpx.Response(200, content=b"x" * 11, request=request)

    with pytest.raises(SafeFetchError) as exc:
        make_fetcher(handler, max_bytes=10).fetch("https://public.test/")
    assert exc.value.code == "response_too_large"


def test_declared_content_length_limit_is_enforced():
    def handler(request):
        return httpx.Response(
            200,
            content=b"",
            headers={"content-length": "11"},
            request=request,
        )

    with pytest.raises(SafeFetchError) as exc:
        make_fetcher(handler, max_bytes=10).fetch("https://public.test/")
    assert exc.value.code == "response_too_large"


def test_sensitive_headers_are_not_forwarded():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200, content=b"ok", request=request)

    make_fetcher(handler).fetch(
        "https://public.test/",
        headers={
            "Authorization": "Bearer secret",
            "Cookie": "session=secret",
            "X-Test": "kept",
        },
    )
    assert "authorization" not in seen
    assert "cookie" not in seen
    assert seen["x-test"] == "kept"
    assert seen["accept-encoding"] == "identity"


def test_timeout_is_mapped():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(SafeFetchError) as exc:
        make_fetcher(handler).fetch("https://public.test/")
    assert exc.value.code == "timeout"


def test_methods_are_restricted():
    with pytest.raises(SafeFetchError) as exc:
        make_fetcher(lambda request: None).fetch(
            "https://public.test/", method="POST"
        )
    assert exc.value.code == "unsupported_method"


def test_invalid_scheme_is_rejected():
    with pytest.raises(SafeFetchError) as exc:
        make_fetcher(lambda request: None).fetch("file:///etc/passwd")
    assert exc.value.code == "unsafe_url"
