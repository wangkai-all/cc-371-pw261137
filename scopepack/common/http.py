"""A tiny threaded HTTP router on top of http.server.

No third-party runtime is available in the target environment, so this keeps
the services dependency-free while still supporting JSON APIs and byte-range
streaming with mid-stream cancellation.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qs, urlsplit

from .util import canonical_json, new_id, read_json_body

log = logging.getLogger("scopepack.http")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details

    def payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": {"code": self.code, "message": self.message}}
        if self.details is not None:
            out["error"]["details"] = self.details
        return out


@dataclass
class Request:
    handler: BaseHTTPRequestHandler
    method: str
    path: str
    query: dict[str, list[str]]
    headers: Mapping[str, str]
    request_id: str
    match: re.Match[str] | None = None
    _body: dict[str, Any] | None = None

    @property
    def remote(self) -> str:
        return self.handler.client_address[0]

    def body(self) -> dict[str, Any]:
        if self._body is None:
            try:
                self._body = read_json_body(self.handler)
            except ValueError as exc:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_body", str(exc)) from exc
        return self._body

    def param(self, name: str) -> str:
        if self.match is None:
            raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, "no_match", "route did not match")
        return self.match.group(name)

    def q(self, name: str, default: str | None = None) -> str | None:
        values = self.query.get(name)
        return values[0] if values else default

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name, default)

    def bearer(self) -> str | None:
        value = self.header("Authorization")
        if value.lower().startswith("bearer "):
            return value[7:].strip()
        return None


@dataclass
class JsonResponse:
    status: int
    body: Any
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class StreamResponse:
    status: int
    content_type: str
    content_length: int
    chunks: Iterable[bytes]
    headers: dict[str, str] = field(default_factory=dict)
    on_abort: Callable[[str], None] | None = None
    on_complete: Callable[[], None] | None = None


HandlerFn = Callable[[Request], JsonResponse | StreamResponse | tuple[int, Any] | None]


class Service:
    def __init__(self, name: str, port: int, host: str = "127.0.0.1"):
        self.name = name
        self.port = port
        self.host = host
        self.routes: list[tuple[str, re.Pattern[str], HandlerFn]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        # Optional per-request guard (e.g. a lock making a shared SQLite
        # connection safe across the threaded server's request threads).
        self.guard: Callable[[], Any] | None = None

    def route(self, method: str, pattern: str) -> Callable[[HandlerFn], HandlerFn]:
        compiled = re.compile("^" + pattern + "$")

        def decorator(fn: HandlerFn) -> HandlerFn:
            self.routes.append((method.upper(), compiled, fn))
            return fn

        return decorator

    def get(self, pattern: str):
        return self.route("GET", pattern)

    def post(self, pattern: str):
        return self.route("POST", pattern)

    def dispatch(self, req: Request) -> JsonResponse | StreamResponse:
        allowed: set[str] = set()
        for method, pattern, fn in self.routes:
            match = pattern.match(req.path)
            if not match:
                continue
            allowed.add(method)
            if method != req.method:
                continue
            req.match = match
            if self.guard is not None:
                with self.guard():
                    result = fn(req)
            else:
                result = fn(req)
            if result is None:
                return JsonResponse(HTTPStatus.NO_CONTENT, None)
            if isinstance(result, tuple):
                return JsonResponse(result[0], result[1])
            if isinstance(result, (dict, list)):
                return JsonResponse(200, result)
            return result
        if allowed:
            raise ApiError(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "method_not_allowed",
                f"{req.method} not allowed for {req.path}",
                {"allowed": sorted(allowed)},
            )
        raise ApiError(HTTPStatus.NOT_FOUND, "not_found", f"no route for {req.path}")

    def make_handler(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = f"Scopepack-{service.name}/1.0"

            def log_message(self, fmt: str, *args: Any) -> None:
                log.info("%s %s %s", self.address_string(), self.command, fmt % args)

            def _handle(self) -> None:
                request_id = self.headers.get("X-Request-Id") or new_id("req")
                parsed = urlsplit(self.path)
                req = Request(
                    handler=self,
                    method=self.command,
                    path=parsed.path,
                    query=parse_qs(parsed.query, keep_blank_values=True),
                    headers=self.headers,
                    request_id=request_id,
                )
                try:
                    response = service.dispatch(req)
                except ApiError as exc:
                    response = JsonResponse(exc.status, exc.payload())
                except Exception:
                    log.exception("unhandled error request_id=%s path=%s", request_id, req.path)
                    response = JsonResponse(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"error": {"code": "internal_error", "message": "internal server error", "request_id": request_id}},
                    )
                self._send(response, request_id)

            def _send(self, response: JsonResponse | StreamResponse, request_id: str) -> None:
                if isinstance(response, JsonResponse):
                    raw = b"" if response.body is None else canonical_json(response.body).encode("utf-8")
                    self.send_response(response.status)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("X-Request-Id", request_id)
                    self.send_header("Cache-Control", "no-store")
                    for key, value in response.headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    if raw:
                        self.wfile.write(raw)
                    return

                self.send_response(response.status)
                self.send_header("Content-Type", response.content_type)
                self.send_header("Content-Length", str(response.content_length))
                self.send_header("X-Request-Id", request_id)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                sent = 0
                try:
                    for chunk in response.chunks:
                        if not chunk:
                            continue
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        sent += len(chunk)
                    if response.on_complete:
                        response.on_complete()
                except (BrokenPipeError, ConnectionResetError, socket.timeout) as exc:
                    self.close_connection = True
                    if response.on_abort:
                        response.on_abort(f"client disconnected: {type(exc).__name__}")
                except Exception as exc:  # application aborts the stream intentionally
                    self.close_connection = True
                    if response.on_abort:
                        response.on_abort(str(exc))
                    log.info("stream aborted request_id=%s sent=%s reason=%s", request_id, sent, exc)

            def do_GET(self) -> None:
                self._handle()

            def do_POST(self) -> None:
                self._handle()

            def do_DELETE(self) -> None:
                self._handle()

        return Handler

    def start(self) -> None:
        self._server = ThreadingHTTPServer((self.host, self.port), self.make_handler())
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name=f"{self.name}-http", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def serve_forever(self) -> None:
        self.start()
        log.info("%s listening on http://%s:%s", self.name, self.host, self.port)
        try:
            assert self._thread
            while self._thread.is_alive():
                self._thread.join(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


def http_json(
    method: str,
    url: str,
    body: Any | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, Any]:
    data = None if body is None else canonical_json(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = raw.decode("utf-8", "replace")
        return exc.code, payload


def http_open(url: str, headers: Mapping[str, str] | None = None, timeout: float = 30.0):
    request = urllib.request.Request(url, method="GET")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    return urllib.request.urlopen(request, timeout=timeout)
