"""Safe request correlation at the authenticated HTTP facade, not key/agent RPC."""
import json
import logging
import re
import secrets
import time

from fastapi import FastAPI

ID_PATTERN = re.compile(r"req_[0-7][0-9A-HJKMNP-TV-Z]{25}", re.ASCII)
STATE_KEY = "undercore_request_id"
LOGGER = logging.getLogger("uvicorn.error.diagnostics")
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_id():
    value = ((int(time.time() * 1000) & ((1 << 48) - 1)) << 80) | secrets.randbits(80)
    return "req_" + "".join(ALPHABET[(value >> shift) & 31] for shift in range(125, -1, -5))


def adopt_authenticated_id(scope):
    # Only the auth guard calls this, after authentication. Duplicate / malformed
    # headers never choose a log key. No caller value is logged on rejection.
    ids = [value for key, value in scope.get("headers", []) if key.lower() == b"x-request-id"]
    if len(ids) == 1 and len(ids[0]) == 30:
        try:
            candidate = ids[0].decode("ascii")
        except UnicodeDecodeError:
            return
        if ID_PATTERN.fullmatch(candidate):
            scope.setdefault("state", {})[STATE_KEY] = candidate


def operation(scope):
    method, path = scope.get("method"), scope.get("path", "")
    if method == "GET" and path == "/v1/health":
        return "health"
    if path == "/v1/clients":
        return {"GET": "list", "POST": "create"}.get(method, "other")
    parts = path.split("/")
    if len(parts) in (4, 5) and parts[:3] == ["", "v1", "clients"] and parts[3]:
        if len(parts) == 4 and method == "GET":
            return "get"
        if len(parts) == 5 and ((method == "GET" and parts[4] in {"configuration", "connection", "amnezia"})
                              or (method == "POST" and parts[4] in {"renew", "replace", "enable", "disable"})):
            return parts[4]
    return "other"


def outcome(status):
    return {401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict",
            410: "expired", 413: "request_too_large", 422: "invalid_request",
            429: "rate_limited", 500: "internal_error", 503: "unavailable"}.get(
                status, "response" if status < 400 else "http_error")


class RequestDiagnostics:
    def __init__(self, app, service):
        self.app, self.service = app, service

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        state = scope.setdefault("state", {})
        state[STATE_KEY] = new_id()
        start, status, result = time.perf_counter(), None, "incomplete"

        async def traced_send(message):
            nonlocal status, result
            if message["type"] == "http.response.start":
                status = message["status"]
                result = outcome(status)
                headers = [(key, value) for key, value in message.get("headers", [])
                           if key.lower() != b"x-request-id"]
                message = {**message, "headers": headers + [(b"x-request-id", state[STATE_KEY].encode("ascii"))]}
            await send(message)

        try:
            await self.app(scope, receive, traced_send)
        except Exception:
            result = "internal_error"
            raise
        finally:
            # Never inspect body, query, path, headers, exception strings or IDs.
            # A broken logging sink must not alter an already committed operation.
            try:
                LOGGER.info(json.dumps({"event": "vpn.api.http", "service": self.service,
                    "request_id": state[STATE_KEY], "operation": operation(scope), "status": status,
                    "duration_ms": max(0, int((time.perf_counter() - start) * 1000)), "outcome": result},
                    separators=(",", ":")))
            except Exception:
                pass


class DiagnosticFastAPI(FastAPI):
    def __init__(self, *, diagnostic_service, **kwargs):
        self.diagnostic_service = diagnostic_service
        super().__init__(**kwargs)

    def build_middleware_stack(self):
        # Outside Starlette's error handler: generated 500s and early auth/body
        # rejections receive the same header too. OpenAPI and routes stay intact.
        return RequestDiagnostics(super().build_middleware_stack(), self.diagnostic_service)
