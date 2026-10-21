"""Bounded HTTP fetching for untrusted URLs.

This is the only outbound HTTP path that new analyzers should use.  It
combines the existing SSRF validator with explicit limits:

* HTTP(S) only, public destinations only, allowed ports only;
* every redirect hop is re-validated, never auto-followed;
* response bodies are streamed and capped;
* short timeouts and no ambient proxy/cookie state.

DNS rebinding remains a residual risk for any HTTP client that resolves
twice.  Deployments that need stronger guarantees should route this client
through an egress proxy with the same allow-list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Optional
from urllib.parse import urljoin

import httpx

from app.security.url_safety import UnsafeUrlError, UrlSafetyValidator

_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "content-length",
    "transfer-encoding",
}


class SafeFetchError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FetchedResponse:
    status_code: int
    url: str
    final_url: str
    headers: dict[str, str]
    body: bytes
    redirects: tuple[str, ...]
    content_type: Optional[str]

    def text(self, limit: int = 2_000_000) -> str:
        return self.body[:limit].decode("utf-8", errors="replace")


class SafeFetcher:
    def __init__(
        self,
        *,
        validator: Optional[UrlSafetyValidator] = None,
        client_factory: Optional[Callable[[], httpx.Client]] = None,
        timeout_seconds: float = 10.0,
        max_bytes: int = 5 * 1024 * 1024,
        max_redirects: int = 5,
    ):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if max_redirects < 0:
            raise ValueError("max_redirects cannot be negative")
        self.validator = validator or UrlSafetyValidator()
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self._client_factory = client_factory or self._default_client

    def _default_client(self) -> httpx.Client:
        # trust_env=False prevents HTTP(S)_PROXY from silently bypassing the
        # validator.  Each fetch gets an isolated client (no cookie carry-over).
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    @staticmethod
    def _clean_headers(headers: Optional[Mapping[str, str]]) -> dict[str, str]:
        clean = {
            key: value
            for key, value in (headers or {}).items()
            if key.lower() not in _SENSITIVE_HEADERS
        }
        clean.setdefault("User-Agent", "PhishNet-SafeFetcher/1.0")
        clean.setdefault("Accept", "*/*")
        # Keep the byte cap meaningful; large compressed payloads should not
        # be inflated silently by the transport.
        clean["Accept-Encoding"] = "identity"
        return clean

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Optional[Mapping[str, str]] = None,
        max_bytes: Optional[int] = None,
    ) -> FetchedResponse:
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise SafeFetchError(
                "unsupported_method", "Only GET and HEAD are allowed"
            )
        limit = max_bytes or self.max_bytes
        if limit <= 0:
            raise SafeFetchError("invalid_limit", "max_bytes must be positive")

        current = url
        redirects: list[str] = []
        request_headers = self._clean_headers(headers)

        try:
            with self._client_factory() as client:
                while True:
                    safe = self._validate(current)
                    try:
                        with client.stream(
                            method,
                            safe.normalized_url,
                            headers=request_headers,
                        ) as response:
                            if response.is_redirect:
                                location = response.headers.get("location")
                                if not location:
                                    raise SafeFetchError(
                                        "missing_location",
                                        "Redirect response has no Location header",
                                    )
                                if len(redirects) >= self.max_redirects:
                                    raise SafeFetchError(
                                        "too_many_redirects",
                                        "Redirect limit exceeded",
                                    )
                                current = urljoin(
                                    safe.normalized_url, location
                                )
                                redirects.append(current)
                                continue

                            declared = response.headers.get("content-length")
                            if declared:
                                try:
                                    declared_size = int(declared)
                                except ValueError:
                                    declared_size = None
                                if declared_size is not None and declared_size > limit:
                                    raise SafeFetchError(
                                        "response_too_large",
                                        "Content-Length exceeds limit",
                                    )

                            chunks: list[bytes] = []
                            total = 0
                            if method != "HEAD":
                                for chunk in response.iter_bytes():
                                    total += len(chunk)
                                    if total > limit:
                                        raise SafeFetchError(
                                            "response_too_large",
                                            "Response body exceeds limit",
                                        )
                                    chunks.append(chunk)

                            body = b"".join(chunks)
                            return FetchedResponse(
                                status_code=response.status_code,
                                url=url,
                                final_url=safe.normalized_url,
                                headers={
                                    key.lower(): value
                                    for key, value in response.headers.items()
                                },
                                body=body,
                                redirects=tuple(redirects),
                                content_type=response.headers.get("content-type"),
                            )
                    except SafeFetchError:
                        raise
                    except httpx.TimeoutException as exc:
                        raise SafeFetchError("timeout", "Request timed out") from exc
                    except httpx.RequestError as exc:
                        raise SafeFetchError(
                            "request_failed", f"Request failed: {type(exc).__name__}"
                        ) from exc
        except UnsafeUrlError as exc:
            raise SafeFetchError(
                "unsafe_url", f"{exc.code}: {exc.detail}"
            ) from exc

    def _validate(self, url: str):
        return self.validator.validate(url)
