"""Live integration test for pylockly.

Run with: python tests/test_live.py <email> <password>

This script tests the full login flow against the real Lockly API:
  1. REST login + lock discovery
  2. MQTT connection + device ping
  3. Status query
"""

from __future__ import annotations

import asyncio
import base64 as b64
import logging
import sys

from pylockly import LocklyAPI, LocklyMqtt

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")


async def main(email: str, password: str) -> None:
    api = LocklyAPI()

    print(f"\n--- Step 1: REST Login as {email} ---")
    try:
        locks = await api.login(email, password)
    except Exception as exc:
        print(f"Login FAILED: {exc}")
        await api.close()
        return

    print(f"Login OK. Found {len(locks)} lock(s):")
    for lock in locks:
        print(f"  - {lock.name} (id={lock.id}, hub={lock.hub_id}, model={lock.model})")
        print(f"    uuid={lock.uuid}, token={lock.token[:20] + '...' if lock.token else 'NONE'}")
        print(f"    iot_dm={lock.iot_dm}, iot_host={lock.iot_host}")
        print(f"    ble_name={lock.ble_name}, fw={lock.lock_firmware}")
        for k in ("mc", "hc", "data4"):
            v = lock.raw.get(k)
            if v:
                print(f"    {k}={v}")

    if not locks:
        print("No locks found; skipping MQTT test.")
        await api.close()
        return

    print(f"\n--- Step 2: MQTT Connect ---")
    mqtt = LocklyMqtt()
    try:
        token = api.auth_token
        if not token:
            print("No auth token available; skipping MQTT.")
        else:
            await mqtt.connect(email, token)
            print(f"MQTT connected: {mqtt.connected}")

            def on_state(states):
                for s in states:
                    print(f"  State update: {s}")

            mqtt.on_device_state(on_state)

            print(f"\n--- Step 3: Ping device {locks[0].id} ---")
            pong = await mqtt.ping(locks[0].id)
            print(f"Ping result: {'PONG' if pong else 'TIMEOUT'}")

            if len(sys.argv) > 3 and sys.argv[3] in ("--lock", "--unlock"):
                directive = sys.argv[3].lstrip("-")
                lock = locks[0]
                mc = lock.master_code
                hc = lock.host_code
                tz_name = lock.raw.get("data4", None)

                from pylockly.ble_cmd import (
                    build_lock_command,
                    build_query_status_command,
                    parse_ble_response,
                    derive_aes_key,
                    _encrypt_master_code,
                )

                print(f"\n--- Step 4: {directive.upper()} via MQTT ---")
                print(f"  Target: {lock.name} (id={lock.id})")
                print(f"  Master code: {mc}")
                print(f"  Host code: {hc}")
                print(f"  Timezone: {tz_name}")

                if not mc:
                    print("  ERROR: No master code found in lock data")
                elif not hc:
                    print("  ERROR: No host code found in lock data")
                else:
                    aes_key = derive_aes_key(mc, lock.id)
                    enc_mc = _encrypt_master_code(mc, lock.id)
                    print(f"  Encrypted MC: {enc_mc}")
                    print(f"  AES key: {aes_key.hex()}")

                    def on_any_msg(msg):
                        print(f"  MQTT msg: {msg.name} payload={msg.payload}")
                    unsub = mqtt.on_message(on_any_msg)

                    # -- Step 4a: QueryLockStatusCmd to get random number --
                    print(f"\n  --- Step 4a: QueryLockStatusCmd (opcode 1E) ---")
                    query_frame = build_query_status_command(
                        mc, lock.id, is_hub=True, tz_name=tz_name,
                    )
                    print(f"  Query frame ({len(query_frame)} bytes): {query_frame.hex()}")

                    random_number = ""
                    try:
                        result = await mqtt.send_lock_command(lock.id, query_frame)
                        resp_content = result.payload.get("commandContent", "")
                        if resp_content:
                            resp_bytes = b64.b64decode(resp_content)
                            print(f"  Query response hex: {resp_bytes.hex()}")

                            parsed = parse_ble_response(resp_bytes, aes_key=aes_key)
                            print(f"  Parsed: {parsed}")

                            if parsed.get("random_number"):
                                random_number = parsed["random_number"]
                                print(f"  >>> Random number: {random_number}")
                            if "is_locked" in parsed:
                                print(f"  >>> Lock state: {'LOCKED' if parsed['is_locked'] else 'UNLOCKED'}")
                        else:
                            print(f"  Query response payload: {result.payload}")
                    except Exception as exc:
                        print(f"  Query FAILED: {exc}")

                    if not random_number:
                        print("\n  WARNING: No random number obtained; trying without it...")

                    await asyncio.sleep(3)

                    # -- Step 4b: Lock/Unlock with random number --
                    is_lock = directive == "lock"
                    print(f"\n  --- Step 4b: {directive.upper()} (opcode=22, AES, random={random_number or 'NONE'}) ---")

                    ble_frame = build_lock_command(
                        master_code=mc,
                        uuid_hex=lock.id,
                        lock=is_lock,
                        pwd=hc,
                        pwd_id=1,
                        encrypt_type=5,
                        opcode="22",
                        via_hub=True,
                        use_aes=True,
                        random_number=random_number,
                    )
                    print(f"  BLE frame ({len(ble_frame)} bytes): {ble_frame.hex()}")

                    try:
                        result = await mqtt.send_lock_command(lock.id, ble_frame)
                        resp_content = result.payload.get("commandContent", "")
                        if resp_content:
                            resp_bytes = b64.b64decode(resp_content)
                            resp_hex = resp_bytes.hex()
                            print(f"  Response hex: {resp_hex}")

                            parsed = parse_ble_response(resp_bytes, aes_key=aes_key)
                            print(f"  Parsed: {parsed}")

                            if not parsed.get("is_error"):
                                print(f"  >>> {directive.upper()} SUCCEEDED! <<<")
                            else:
                                err = parsed.get("error_hex", "unknown")
                                print(f"  >>> ERROR: {err}")
                        else:
                            print(f"  Response payload: {result.payload}")
                    except Exception as exc:
                        print(f"  {directive.upper()} FAILED: {exc}")

                    print("\n  Waiting 15s for state updates...")
                    await asyncio.sleep(15)
                    unsub()
            else:
                print("\nListening for state updates for 15 seconds...")
                print("(pass --lock or --unlock as 4th arg to test commands)")
                await asyncio.sleep(15)

    except Exception as exc:
        print(f"MQTT test failed: {exc}")
    finally:
        await mqtt.disconnect()
        await api.close()

    print("\n--- Done ---")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <email> <password> [--lock|--unlock]")
        sys.exit(1)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
