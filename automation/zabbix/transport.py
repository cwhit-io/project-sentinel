"""Bounded, no-redirect Zabbix JSON-RPC transport for protected commissioning."""

from __future__ import annotations

import http.client
import json
import ssl
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from automation.zabbix.credentials import CredentialProvider, EphemeralSecret, ReadCredentialHandle

API_PATH = "/api_jsonrpc.php"
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
READ_METHODS = frozenset({"apiinfo.version", "host.get", "template.get", "hostgroup.get", "httptest.get", "item.get"})
_TRANSPORT_ERROR = "Zabbix transport failed"


def _erase(value: bytearray | None) -> None:
    if value is not None:
        for index in range(len(value)):
            value[index] = 0


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("invalid Zabbix response")
        value[key] = child
    return value


def _constant(_: str) -> None:
    raise ValueError("invalid Zabbix response")


@dataclass(frozen=True)
class TransportContract:
    endpoint: str
    trust_id: str
    allow_commissioning_http: bool = False
    timeout_seconds: float = 5.0
    max_response_bytes: int = MAX_RESPONSE_BYTES
    max_request_bytes: int = MAX_REQUEST_BYTES

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.endpoint)
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid Zabbix endpoint") from exc
        if parsed.scheme not in {"https", "http"} or parsed.path != API_PATH or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
            raise ValueError("invalid Zabbix endpoint")
        if not parsed.hostname or type(self.trust_id) is not str or not self.trust_id:
            raise ValueError("invalid Zabbix transport identity")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid Zabbix endpoint port")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        default_port = 443 if parsed.scheme == "https" else 80
        canonical = f"{parsed.scheme}://{host}{f':{port}' if port is not None and port != default_port else ''}{API_PATH}"
        if self.endpoint != canonical:
            raise ValueError("Zabbix endpoint must be canonical")
        if parsed.scheme == "http" and not (self.allow_commissioning_http and parsed.hostname in {"127.0.0.1", "::1"} and port is not None):
            raise ValueError("commissioning HTTP requires an opted-in numeric loopback endpoint and explicit port")
        if parsed.scheme == "https" and self.allow_commissioning_http:
            raise ValueError("HTTP opt-in is invalid for HTTPS")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or not 0 < self.timeout_seconds <= 30:
            raise ValueError("invalid Zabbix timeout")
        if type(self.max_response_bytes) is not int or not 1 <= self.max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("invalid Zabbix response bound")
        if type(self.max_request_bytes) is not int or not 1 <= self.max_request_bytes <= MAX_REQUEST_BYTES:
            raise ValueError("invalid Zabbix request bound")

    @property
    def identity(self) -> dict[str, Any]:
        parsed = urlsplit(self.endpoint)
        return {"scheme": parsed.scheme, "host": parsed.hostname, "port": parsed.port or 443,
                "path": API_PATH, "timeout_seconds": self.timeout_seconds,
                "max_response_bytes": self.max_response_bytes, "redirects": False, "proxies": False,
                "cookies": False, "retries": 0}


class JsonRpcTransport:
    """Direct stdlib connection: no proxy discovery, redirect, cookie jar, or retry."""

    def __init__(self, contract: TransportContract, provider: CredentialProvider,
                 handle: ReadCredentialHandle,
                 *, connection_factory: Callable[..., Any] | None = None,
                 ssl_context: ssl.SSLContext | None = None):
        if type(contract) is not TransportContract:
            raise TypeError("transport requires the exact immutable contract")
        if type(handle) is not ReadCredentialHandle:
            raise TypeError("transport requires the exact read credential handle")
        if not isinstance(provider, CredentialProvider):
            raise TypeError("credential provider does not implement the protected interface")
        if ssl_context is not None and (ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname):
            raise ValueError("HTTPS trust context must require certificate and hostname verification")
        self._contract, self._provider, self._handle = contract, provider, handle
        self._factory, self._ssl_context = connection_factory, ssl_context
        self._next_id = 1

    @property
    def contract(self) -> TransportContract:
        return self._contract

    @property
    def handle(self) -> ReadCredentialHandle:
        return self._handle

    def call(self, method: str, params: dict[str, Any]) -> Any:
        # This lowest network boundary rejects every non-discovery method before
        # inspecting parameters, resolving a credential, or constructing I/O.
        if type(method) is not str or method not in READ_METHODS:
            raise PermissionError("Zabbix transport is limited to read-only discovery")
        if type(params) is not dict:
            raise ValueError("invalid Zabbix request")
        request_id = self._next_id
        self._next_id += 1
        # Acquire and consume are deliberately one sanitized boundary.  The
        # exact container lets us erase its buffer even if consume itself fails.
        try:
            credential = self._provider.acquire(self.handle)
        except Exception:
            raise RuntimeError(_TRANSPORT_ERROR) from None
        if type(credential) is not EphemeralSecret:
            _erase(credential if type(credential) is bytearray else None)
            raise RuntimeError(_TRANSPORT_ERROR) from None
        secret = getattr(credential, "_value", None)
        if type(secret) is not bytearray or not secret:
            _erase(secret if type(secret) is bytearray else None)
            raise RuntimeError(_TRANSPORT_ERROR) from None
        try:
            consumed = credential.consume()  # immediately before call
        except Exception:
            _erase(secret)
            raise RuntimeError(_TRANSPORT_ERROR) from None
        if type(consumed) is not bytearray or consumed is not secret or not consumed:
            _erase(consumed if type(consumed) is bytearray and consumed is not secret else None)
            _erase(secret)
            raise RuntimeError(_TRANSPORT_ERROR) from None
        body: bytearray | None = None
        try:
            try:
                token = bytes(secret).decode("utf-8", errors="strict")
                # Zabbix explicitly forbids the "auth" field on apiinfo.version.
                # Sending it causes {"error":{"code":-32602,"message":"Invalid params."}}.
                # For all other methods in the read allowlist, the auth token is required.
                payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params, "id": request_id}
                if method != "apiinfo.version":
                    payload["auth"] = token
                body = bytearray(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                token = ""
                if len(body) > self.contract.max_request_bytes:
                    raise ValueError("invalid Zabbix request")
            except (TypeError, ValueError, UnicodeError):
                raise ValueError("invalid Zabbix request") from None
            except Exception:
                raise RuntimeError(_TRANSPORT_ERROR) from None

            parsed = urlsplit(self.contract.endpoint)
            factory = self._factory
            if factory is None:
                factory = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            kwargs: dict[str, Any] = {"timeout": self.contract.timeout_seconds}
            if parsed.scheme == "https" and factory is http.client.HTTPSConnection:
                kwargs["context"] = self._ssl_context or ssl.create_default_context()
            connection = None
            try:
                connection = factory(parsed.hostname, parsed.port or 443, **kwargs)
                try:
                    connection.request("POST", API_PATH, body=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
                    response = connection.getresponse()
                    raw = response.read(self.contract.max_response_bytes + 1)
                finally:
                    if connection is not None:
                        connection.close()
            except Exception:
                raise RuntimeError(_TRANSPORT_ERROR) from None
        finally:
            _erase(secret)
            _erase(body)
        try:
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            content_encoding = response.getheader("Content-Encoding")
        except Exception:
            raise RuntimeError(_TRANSPORT_ERROR) from None
        try:
            if (response.status != 200 or len(raw) > self.contract.max_response_bytes
                    or content_type != "application/json" or content_encoding not in {None, "identity"}):
                raise RuntimeError(_TRANSPORT_ERROR)
        except RuntimeError:
            raise
        except Exception:
            raise RuntimeError(_TRANSPORT_ERROR) from None
        try:
            document = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_constant=_constant)
        except (UnicodeError, json.JSONDecodeError, ValueError):
            raise ValueError("invalid Zabbix response") from None
        except Exception:
            raise RuntimeError(_TRANSPORT_ERROR) from None
        if (not isinstance(document, dict) or document.get("jsonrpc") != "2.0"
                or type(document.get("id")) is not int or document.get("id") != request_id):
            raise ValueError("invalid Zabbix response")
        if set(document) == {"jsonrpc", "id", "result"}:
            return document["result"]
        error = document.get("error")
        if (set(document) == {"jsonrpc", "id", "error"} and isinstance(error, dict)
                and set(error) == {"code", "message", "data"} and type(error["code"]) is int
                and isinstance(error["message"], str) and isinstance(error["data"], str)):
            raise RuntimeError("Zabbix API returned an error")
        raise ValueError("invalid Zabbix response")
