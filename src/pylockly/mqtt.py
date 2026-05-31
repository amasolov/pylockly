"""Async MQTT client for the Lockly Cloud API.

Connects to the Lockly MQTT broker (AWS ELB) and handles:
  - Lock commands (lockCommandRequest/lockCommandResponse)
  - Hub commands (hubCommandRequest/hubCommandResponse)
  - Device state subscriptions (deviceStateCallback)
  - Ping/pong connectivity checks
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
import uuid
from collections.abc import Callable
from typing import Any

import aiomqtt

from .const import (
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_NAMESPACE,
    MQTT_PUBLISH_TOPIC,
    MQTT_QOS,
    MQTT_RESPONSE_TIMEOUT,
    REQ_HUB_COMMAND,
    REQ_LOCK_COMMAND,
    REQ_PING,
    RESP_DEVICE_STATE,
    RESP_EXCEPTION,
    RESP_HUB_COMMAND,
    RESP_LOCK_COMMAND,
    RESP_PONG,
)
from .exceptions import LocklyMqttError, LocklyTimeoutError
from .models import DeviceState, MqttMessage

_LOGGER = logging.getLogger(__name__)


class LocklyMqtt:
    """Async MQTT client for real-time Lockly hub communication."""

    def __init__(self) -> None:
        self._client: aiomqtt.Client | None = None
        self._listener_task: asyncio.Task[None] | None = None
        self._pending: dict[str, asyncio.Future[MqttMessage]] = {}
        self._state_callbacks: list[Callable[[list[DeviceState]], None]] = []
        self._message_callbacks: list[Callable[[MqttMessage], None]] = []
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    async def connect(
        self,
        email: str,
        token: str,
        client_id: str | None = None,
    ) -> None:
        """Connect to the Lockly MQTT broker.

        Args:
            email: Lockly account email (used as MQTT username).
            token: Bearer token from REST login (without "Bearer " prefix).
            client_id: MQTT client ID. Generated if not provided.
        """
        if self._connected:
            return

        if client_id is None:
            client_id = uuid.uuid4().hex

        password = token.removeprefix("Bearer ").removeprefix("bearer ")
        username = email.lower()

        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE

        self._client = aiomqtt.Client(
            hostname=MQTT_BROKER_HOST,
            port=MQTT_BROKER_PORT,
            username=username,
            password=password,
            identifier=client_id,
            tls_context=tls_ctx,
        )

        await self._client.__aenter__()
        self._connected = True
        self._listener_task = asyncio.create_task(self._listen())
        _LOGGER.info("MQTT connected as %s (client_id=%s)", username, client_id)

    async def disconnect(self) -> None:
        """Disconnect from the MQTT broker."""
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None

        if self._client:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:
                pass
            self._client = None

        self._connected = False

        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

        _LOGGER.info("MQTT disconnected")

    async def _listen(self) -> None:
        """Background task that processes incoming MQTT messages."""
        if self._client is None:
            return

        try:
            async for message in self._client.messages:
                try:
                    payload_str = message.payload
                    if isinstance(payload_str, bytes):
                        payload_str = payload_str.decode("utf-8")
                    data = json.loads(payload_str)
                    msg = MqttMessage.from_json(data)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    _LOGGER.warning("Failed to parse MQTT message: %s", exc)
                    continue

                _LOGGER.debug("MQTT received: %s (id=%s)", msg.name, msg.request_id)

                for cb in self._message_callbacks:
                    try:
                        cb(msg)
                    except Exception:
                        _LOGGER.exception("Error in message callback")

                if msg.name == RESP_DEVICE_STATE:
                    states = DeviceState.from_mqtt_payload(msg.payload)
                    for cb in self._state_callbacks:
                        try:
                            cb(states)
                        except Exception:
                            _LOGGER.exception("Error in state callback")

                if msg.request_id and msg.request_id in self._pending:
                    fut = self._pending.pop(msg.request_id)
                    if not fut.done():
                        fut.set_result(msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("MQTT listener error")
            self._connected = False

    def _make_envelope(
        self, name: str, payload: dict[str, Any], request_id: str | None = None
    ) -> tuple[str, str]:
        """Build an MQTT message envelope, returning (request_id, json_str)."""
        if request_id is None:
            request_id = str(uuid.uuid4())
        msg = MqttMessage(
            request_id=request_id,
            name=name,
            timestamp=int(time.time() * 1000),
            payload=payload,
        )
        return request_id, json.dumps(msg.to_json())

    async def _publish_and_wait(
        self,
        name: str,
        payload: dict[str, Any],
        timeout: float = MQTT_RESPONSE_TIMEOUT,
    ) -> MqttMessage:
        """Publish a message and wait for the correlated response."""
        if not self._connected or self._client is None:
            raise LocklyMqttError("Not connected to MQTT broker")

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[MqttMessage] = loop.create_future()

        request_id, msg_json = self._make_envelope(name, payload)
        self._pending[request_id] = fut

        try:
            await self._client.publish(
                MQTT_PUBLISH_TOPIC, msg_json.encode("utf-8"), qos=MQTT_QOS
            )
            _LOGGER.debug("MQTT published: %s (id=%s)", name, request_id)
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(request_id, None)
            raise LocklyTimeoutError(
                f"MQTT response timeout for {name} (id={request_id})"
            )
        except Exception:
            self._pending.pop(request_id, None)
            raise

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_lock_command(
        self, device_id: str, ble_data: bytes
    ) -> MqttMessage:
        """Send a BLE command to a lock through its hub via MQTT.

        Args:
            device_id: The lock UUID (DoorLock.id).
            ble_data: Raw BLE command bytes to forward.

        Returns:
            The response MqttMessage with payload containing commandContent.
        """
        import base64 as b64

        payload = {
            "deviceId": device_id,
            "commandName": "forward",
            "commandContent": b64.b64encode(ble_data).decode("ascii"),
        }
        return await self._publish_and_wait(REQ_LOCK_COMMAND, payload)

    async def send_hub_command(
        self, hub_id: str, command_content: dict[str, Any]
    ) -> MqttMessage:
        """Send a command directly to a hub.

        Args:
            hub_id: The hub identifier.
            command_content: Command-specific JSON payload.
        """
        payload = {
            "deviceId": hub_id,
            "commandName": "forward",
            "commandContent": command_content,
        }
        response = await self._publish_and_wait(REQ_HUB_COMMAND, payload)

        if response.payload.get("code", -1) != 0:
            raise LocklyMqttError(
                f"Hub command failed: {response.payload.get('message', 'unknown error')}"
            )
        return response

    async def ping(self, device_id: str) -> bool:
        """Send a ping and wait for pong. Returns True if successful."""
        try:
            response = await self._publish_and_wait(
                REQ_PING, {"deviceId": device_id}
            )
            return response.name == RESP_PONG
        except LocklyTimeoutError:
            return False

    def on_device_state(
        self, callback: Callable[[list[DeviceState]], None]
    ) -> Callable[[], None]:
        """Register a callback for device state updates.

        Returns a callable that unregisters the callback when called.
        """
        self._state_callbacks.append(callback)
        return lambda: self._state_callbacks.remove(callback)

    def on_message(
        self, callback: Callable[[MqttMessage], None]
    ) -> Callable[[], None]:
        """Register a callback for all incoming MQTT messages.

        Returns a callable that unregisters the callback when called.
        """
        self._message_callbacks.append(callback)
        return lambda: self._message_callbacks.remove(callback)
