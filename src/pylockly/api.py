"""Async REST client for the Lockly Cloud API.

Implements the login flow (login -> qrylknew -> user key + lock list)
and authenticated endpoints (getstatus, asyncSend, hub/getinfo).
"""

from __future__ import annotations

import base64
import json
import logging
import time as time_mod
import uuid
from datetime import datetime, timezone
from typing import Any

import aiohttp

from .const import (
    CLIENT_COUNTRY,
    CLIENT_LOCALE,
    CLIENT_OS,
    CLIENT_VER,
    CLIENT_VERSION_NAME,
    MMS_BASE_URL,
    MQTT_NAMESPACE,
    REST_BASE_URL,
)
from .crypto import (
    decrypt_anonymous,
    decrypt_user,
    encrypt_anonymous,
    encrypt_user,
    hash_password,
)
from .exceptions import LocklyApiError, LocklyAuthError
from .models import DoorLock, HubMqttInfo, LockEvent

_LOGGER = logging.getLogger(__name__)


class LocklyAPI:
    """Async REST client for the Lockly Cloud API."""

    def __init__(
        self,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self._session = session
        self._owns_session = session is None
        self._device_id: str = uuid.uuid4().hex
        self._auth_token: str | None = None
        self._user_key: bytes | None = None
        self._email: str | None = None

    @property
    def authenticated(self) -> bool:
        return self._user_key is not None and self._auth_token is not None

    @property
    def email(self) -> str | None:
        return self._email

    @property
    def auth_token(self) -> str | None:
        return self._auth_token

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        return self._session

    async def close(self) -> None:
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    def _build_envelope(
        self,
        parameters: dict[str, Any],
        *,
        user_encryption: bool = True,
        token: str | None = None,
    ) -> dict[str, Any]:
        """Build the JSON request envelope with encrypted para field."""
        param_bytes = json.dumps(parameters).encode("utf-8")

        if user_encryption:
            if self._user_key is None:
                raise LocklyAuthError("Not authenticated; call login() first")
            encrypted = encrypt_user(self._user_key, param_bytes)
        else:
            encrypted = encrypt_anonymous(param_bytes)

        envelope: dict[str, Any] = {
            "appType": "LOCKLY",
            "ctry": CLIENT_COUNTRY,
            "dvid": self._device_id,
            "locale": CLIENT_LOCALE,
            "os": CLIENT_OS,
            "para": base64.b64encode(encrypted).decode("ascii"),
            "rid1": "",
            "rid2": "",
            "tk": token or "",
            "ver": CLIENT_VER,
            "versionName": CLIENT_VERSION_NAME,
        }
        return envelope

    async def _request(
        self,
        endpoint: str,
        *,
        body: Any = None,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        """Make a POST request to the Lockly REST API."""
        session = await self._ensure_session()
        url = f"{REST_BASE_URL}{endpoint}"

        headers: dict[str, str] = {"Content-Type": content_type}
        if self._auth_token:
            headers["Authorization"] = self._auth_token

        if isinstance(body, dict):
            raw_body = json.dumps(body)
        elif isinstance(body, str):
            raw_body = body
        else:
            raw_body = body

        _LOGGER.debug("POST %s", url)

        async with session.post(url, headers=headers, data=raw_body) as resp:
            response_json = await resp.json(content_type=None)

            if str(response_json.get("cod")) != "200":
                code = str(response_json.get("cod", "unknown"))
                msg = response_json.get("msg")
                _LOGGER.debug(
                    "API error on %s: cod=%s msg=%s full=%s",
                    endpoint, code, msg, response_json,
                )
                if code in ("401", "403"):
                    raise LocklyAuthError(f"Authentication failed: {msg}")
                raise LocklyApiError(code, msg)

            auth = resp.headers.get("Authorization")
            if auth:
                self._auth_token = auth

            return response_json

    async def _json_request(
        self,
        endpoint: str,
        parameters: dict[str, Any],
        *,
        user_encryption: bool = True,
    ) -> dict[str, Any]:
        """Make an encrypted JSON API request."""
        envelope = self._build_envelope(
            parameters, user_encryption=user_encryption
        )
        return await self._request(endpoint, body=envelope)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def login(self, email: str, password: str) -> list[DoorLock]:
        """Authenticate and return the list of door locks.

        This performs the full login flow:
          1. POST login (RSA-encrypted credentials)
          2. POST qrylknew (RSA-encrypted account query)
          3. Decrypt user 3DES key from response
          4. Decrypt each door lock entry with user key
        """
        self._email = email

        await self._json_request(
            "login",
            {"acct": email, "pw": hash_password(password)},
            user_encryption=False,
        )

        account_data = await self._json_request(
            "qrylknew",
            {"acct": email},
            user_encryption=False,
        )

        encrypted_key = base64.b64decode(account_data["key"])
        decrypted_key_str = decrypt_anonymous(encrypted_key).decode("utf-8")
        self._user_key = base64.b64decode(decrypted_key_str)

        locks: list[DoorLock] = []
        for entry_b64 in account_data.get("dl", []):
            entry_encrypted = base64.b64decode(entry_b64)
            entry_json_bytes = decrypt_user(self._user_key, entry_encrypted)
            entry_data = json.loads(entry_json_bytes.decode("utf-8"))
            locks.append(DoorLock.from_json(entry_data))

        _LOGGER.info("Logged in as %s, found %d lock(s)", email, len(locks))
        return locks

    async def get_locks(self) -> list[DoorLock]:
        """Re-fetch the lock list (requires prior login)."""
        if not self._email:
            raise LocklyAuthError("Not authenticated; call login() first")
        account_data = await self._json_request(
            "qrylknew",
            {"acct": self._email},
            user_encryption=False,
        )

        locks: list[DoorLock] = []
        for entry_b64 in account_data.get("dl", []):
            entry_encrypted = base64.b64decode(entry_b64)
            entry_json_bytes = decrypt_user(self._user_key, entry_encrypted)
            entry_data = json.loads(entry_json_bytes.decode("utf-8"))
            locks.append(DoorLock.from_json(entry_data))
        return locks

    async def get_status(
        self, hub_id: str, device_id: str | None = None
    ) -> dict[str, Any]:
        """Query hub/lock status via the getstatus endpoint."""
        params: dict[str, Any] = {"acct": self._email, "hubid": hub_id}
        if device_id:
            params["dv"] = device_id
        return await self._json_request("getstatus", params)

    async def get_hub_mqtt_info(
        self, device_id: str, hub_id: str
    ) -> HubMqttInfo:
        """Fetch MQTT credentials for a hub via hub/getinfo."""
        data = await self._json_request(
            "hub/getinfo",
            {"acct": self._email, "dv": device_id, "hubid": hub_id},
        )
        return HubMqttInfo.from_json(data)

    async def lock(self, lock: DoorLock) -> dict[str, Any]:
        """Lock the device via the pushUnlock (ebUnlockEvent) endpoint."""
        return await self._push_lock_command(lock, is_lock=True)

    async def unlock(self, lock: DoorLock) -> dict[str, Any]:
        """Unlock the device via the pushUnlock (ebUnlockEvent) endpoint."""
        return await self._push_lock_command(lock, is_lock=False)

    async def _push_lock_command(
        self, lock: DoorLock, *, is_lock: bool
    ) -> dict[str, Any]:
        """Send lock/unlock via the ebUnlockEvent endpoint.

        Uses RSA anonymous encryption (not 3DES user encryption).
        The token is the device-specific token from the lock data,
        not the HTTP session auth token.
        """
        import time
        device_id = lock.uuid or lock.id
        device_token = lock.token
        if not device_token:
            raise LocklyApiError("0", "Lock has no device token; cannot send push command")
        params = {
            "deviceId": device_id,
            "unlock": 1 if is_lock else 0,
            "token": device_token,
            "nonce": uuid.uuid4().hex[:16],
            "timestamp": int(time.time() * 1000),
        }
        return await self._json_request(
            "ebUnlockEvent", params, user_encryption=False
        )

    async def async_send(
        self,
        lock_id: str,
        ble_cmd_hex: str,
        hub_device_name: str,
        *,
        directive: str | None = None,
    ) -> str | None:
        """Send a BLE command to the lock through the hub via asyncSend.

        Returns the req_msg_id for correlating the MQTT response.
        """
        params: dict[str, Any] = {
            "acct": self._email,
            "cmd": ble_cmd_hex,
            "dv": lock_id,
            "mdna": hub_device_name,
        }
        if directive:
            params["directive"] = directive

        result = await self._json_request("asyncSend", params)
        return result.get("req_msg_id")

    async def query_event_log(
        self,
        device_id: str,
        start_ms: int = 0,
        end_ms: int = 0,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[LockEvent]:
        """Query lock event log via the MMS REST handler.

        Uses the apiserv04c MMS endpoint (plain JSON, no DES3).
        Timestamps are milliseconds since epoch; 0 means "open-ended".

        Returns a list of LockEvent objects.
        """
        if not self._auth_token:
            raise LocklyAuthError("Not authenticated; call login() first")

        def _fmt(ms: int) -> str:
            return datetime.fromtimestamp(
                ms / 1000, tz=timezone.utc
            ).strftime("%Y%m%d%H%M%S")

        body: dict[str, Any] = {
            "header": {
                "namespace": MQTT_NAMESPACE,
                "name": "lockEventLogQueryRequest",
                "requestId": str(uuid.uuid4()),
                "timestamp": int(time_mod.time() * 1000),
            },
            "payload": {
                "deviceId": device_id,
                "startTime": _fmt(start_ms) if start_ms else _fmt(0),
                "endTime": _fmt(end_ms) if end_ms else _fmt(
                    int(time_mod.time() * 1000)
                ),
                "offset": offset,
                "limit": limit,
            },
        }

        session = await self._ensure_session()
        url = f"{MMS_BASE_URL}v1/proto/handler"
        headers = {
            "Content-Type": "application/json",
            "Authorization": self._auth_token,
        }

        _LOGGER.debug("POST %s (event log query)", url)

        async with session.post(
            url, headers=headers, data=json.dumps(body)
        ) as resp:
            data = await resp.json(content_type=None)

        cod = data.get("cod")
        if cod not in (0, 200, "200"):
            raise LocklyApiError(
                str(cod), data.get("msg", "event log query failed")
            )

        auth = data.get("Authorization")
        if auth:
            self._auth_token = auth

        resp_header = data.get("header", {})
        if resp_header.get("name") == "exception":
            err = data.get("payload", {})
            raise LocklyApiError(
                str(err.get("code", 0)), err.get("message", "")
            )

        payload = data.get("payload", {})
        return LockEvent.from_log_response(payload)
