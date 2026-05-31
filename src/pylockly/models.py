"""Data models for the Lockly API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DoorLock:
    """A Lockly door lock, as returned by the qrylknew endpoint.

    JSON field names match the Lockly API wire format (e.g. "na" for name).
    """

    id: str
    name: str
    hub_id: str
    model: str
    ble_name: str
    timezone: str
    hub_firmware: str
    lock_firmware: str
    locking_mode: str
    auto_lock: int
    property_id: int
    room_id: int

    iot_dm: str
    iot_secret: str
    iot_prod_key: str
    iot_host: str

    master_code: str = ""
    host_code: str = ""
    uuid: str = ""
    token: str = ""

    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> DoorLock:
        return cls(
            id=data["ID"],
            name=data.get("na", ""),
            hub_id=data.get("hubid", ""),
            model=data.get("mod", ""),
            ble_name=data.get("blename", ""),
            timezone=data.get("tz", ""),
            hub_firmware=data.get("hubver", ""),
            lock_firmware=data.get("fwv", ""),
            locking_mode=data.get("lockingMode", ""),
            auto_lock=int(data.get("autoLock", 0)),
            property_id=int(data.get("propertyId", 0)),
            room_id=int(data.get("roomId", 0)),
            iot_dm=data.get("iotdm", ""),
            iot_secret=data.get("iotsecret", ""),
            iot_prod_key=data.get("iotprodkey", ""),
            iot_host=data.get("iothost", ""),
            master_code=str(data.get("mc", "")),
            host_code=str(data.get("hc", "")),
            uuid=data.get("uuid", data.get("ID", "")),
            token=data.get("token", ""),
            raw=data,
        )


@dataclass
class DeviceState:
    """Real-time state update from deviceStateCallback MQTT messages."""

    device_id: str
    lock_state: str | None = None
    door_state: str | None = None
    battery: int | None = None
    rssi: int | None = None
    timestamp: int | None = None

    @classmethod
    def from_mqtt_payload(cls, payload: dict[str, Any]) -> list[DeviceState]:
        """Parse the payload.items array from a deviceStateCallback."""
        results: list[DeviceState] = []
        for item in payload.get("items", []):
            device_id = item.get("deviceId", "")
            state = cls(device_id=device_id)
            for status in item.get("states", []):
                key = status.get("statusKey", "")
                value = status.get("statusValue")
                ts = status.get("timestamp")
                if ts is not None:
                    state.timestamp = int(ts)
                if key == "lock":
                    state.lock_state = value
                elif key == "magnet":
                    state.door_state = value
                elif key == "health":
                    try:
                        state.battery = int(value)
                    except (TypeError, ValueError):
                        pass
            results.append(state)
        return results


UNLOCK_TYPE_NAMES: dict[str, str] = {
    "1": "app",
    "2": "keypad",
    "3": "guest_code",
    "4": "physical_key",
    "5": "family_code",
    "10": "rfid",
    "11": "fingerprint",
    "12": "one_time_code",
    "32": "guest_fingerprint",
    "63": "e_badge_unlock",
    "64": "e_badge_lock",
}


@dataclass
class LockEvent:
    """A single lock event from the event log."""

    event_id: int
    event_type: str
    user_id: str
    time: str
    lock_name: str | None = None
    lock_user_name: str | None = None
    timestamp: int = 0

    @property
    def event_type_name(self) -> str:
        return UNLOCK_TYPE_NAMES.get(self.event_type, f"unknown_{self.event_type}")

    @classmethod
    def from_log_response(cls, payload: dict[str, Any]) -> list[LockEvent]:
        """Parse the items array from a lockEventLogQueryResponse."""
        results: list[LockEvent] = []
        for item in payload.get("items", []):
            results.append(cls(
                event_id=item.get("eventId", 0),
                event_type=str(item.get("eventType", "")),
                user_id=str(item.get("userId", "")),
                time=item.get("time", ""),
                lock_name=item.get("lockName"),
                lock_user_name=item.get("lockUserName"),
                timestamp=int(item.get("timestamp", 0)),
            ))
        return results


@dataclass
class HubMqttInfo:
    """MQTT credentials for a hub, returned by hub/getinfo REST endpoint."""

    device_name: str
    device_secret: str
    product_key: str
    mqtt_host: str
    hub_id: str
    hub_version: str

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> HubMqttInfo:
        return cls(
            device_name=data.get("iotdm", ""),
            device_secret=data.get("iotsecret", ""),
            product_key=data.get("iotprodkey", ""),
            mqtt_host=data.get("iothost", ""),
            hub_id=data.get("name", ""),
            hub_version=data.get("hubver", ""),
        )


@dataclass
class MqttMessage:
    """Parsed MQTT message envelope."""

    request_id: str
    name: str
    timestamp: int
    payload: dict[str, Any]
    namespace: str = "com.lockly"

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> MqttMessage:
        header = data.get("header", {})
        return cls(
            request_id=header.get("requestId", ""),
            name=header.get("name", ""),
            timestamp=header.get("timestamp", 0),
            namespace=header.get("namespace", "com.lockly"),
            payload=data.get("payload", {}),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "header": {
                "namespace": self.namespace,
                "name": self.name,
                "requestId": self.request_id,
                "timestamp": self.timestamp,
            },
            "payload": self.payload,
        }
