# pylockly

Python client for the Lockly Cloud API (REST + MQTT).

Provides async access to Lockly smart locks via the cloud API, including:

- REST authentication (login, account query, lock discovery)
- MQTT real-time communication (lock commands, device state updates)
- Encryption layer (RSA anonymous + 3DES user encryption)

## Installation

```bash
pip install pylockly
```

## Quick start

```python
import asyncio
from pylockly import LocklyAPI, LocklyMqtt

async def main():
    api = LocklyAPI()
    locks = await api.login("user@example.com", "password")

    for lock in locks:
        print(f"{lock.name} (hub: {lock.hub_id})")

    # Connect MQTT for real-time state
    mqtt = LocklyMqtt()
    await mqtt.connect(api.email, api.auth_token)

    # Register for state updates
    mqtt.on_device_state(lambda states: print(states))

    await api.close()
    await mqtt.disconnect()

asyncio.run(main())
```

## Status

Alpha. This is an unofficial reverse-engineered client. Use at your own risk.
