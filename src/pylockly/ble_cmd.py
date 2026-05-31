"""Build BLE lock/unlock command frames for Lockly locks.

Reverse-engineered from the Lockly Android app (v3.3.0).
These BLE frames are sent via MQTT lockCommandRequest as base64 commandContent.
"""

from __future__ import annotations

import base64
import time
from datetime import datetime, timezone

from Crypto.Cipher import AES


CRC8_TABLE = [0, 49, 98, 83, 196, 245, 166, 151, 185, 136, 219, 234, 125, 76, 31, 46]

HEAD_CMD = bytes([0xA1, 0xB2, 0xC3, 0xD4])


def _crc8(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = ((crc << 4) & 0xFF) ^ CRC8_TABLE[((crc >> 4) ^ (b >> 4)) & 0x0F]
        crc = ((crc << 4) & 0xFF) ^ CRC8_TABLE[((crc >> 4) ^ (b & 0x0F)) & 0x0F]
    return crc & 0xFF


def _hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def _encrypt_master_code(master_code: str, uuid_hex: str) -> str:
    """XOR master code digit values with UUID hex bytes, return hex string.

    Equivalent to BluetoothBean.getHostEncryptMc() -> HexUtils.g(mc, uuid).
    """
    mc_bytes = bytes(int(c) for c in master_code)
    uuid_bytes = _hex_to_bytes(uuid_hex)
    xored = _xor_bytes(mc_bytes, uuid_bytes)
    return xored.hex()


def _expand_pwd(pwd: str) -> str:
    """Expand each digit to '0X' hex pair. HexUtils.d()."""
    return "".join(f"0{c}" for c in pwd)


def _pad_hex(s: str) -> str:
    """Pad single-char hex string to 2 chars."""
    return f"0{s}" if len(s) == 1 else s


def derive_aes_key(master_code: str, uuid_hex: str) -> bytes:
    """Derive the 16-byte AES key from master code and UUID.

    Equivalent to DataUtils.h(masterCode, uuid).
    """
    mc_expanded = _hex_to_bytes(_expand_pwd(master_code))
    uuid_bytes = _hex_to_bytes(uuid_hex)
    if len(uuid_bytes) < 12:
        raise ValueError(f"UUID too short for AES key derivation: {len(uuid_bytes)} bytes")

    key = bytearray(16)
    for i in range(len(master_code)):
        key[i] = uuid_bytes[i % len(uuid_hex)] ^ mc_expanded[i]
    for i in range(8, 12):
        key[i] = uuid_bytes[i] ^ mc_expanded[i - 8]
    for i in range(12, 16):
        key[i] = uuid_bytes[i - 12]

    return bytes(key)


def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-ECB encrypt (NoPadding). Data must be a multiple of 16 bytes."""
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-ECB decrypt (NoPadding). Data must be a multiple of 16 bytes."""
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def _zero_pad_hex(hex_str: str) -> str:
    """Return zero-padding hex chars needed to align to 16-byte boundary.

    Equivalent to DataUtils.p().
    """
    byte_count = len(hex_str) // 2
    remainder = byte_count % 16
    if remainder > 0:
        pad_bytes = 16 - remainder
        return "00" * pad_bytes
    return ""


def _build_aes_frame(
    aes_key: bytes,
    plaintext_hex: str,
    encrypt_type: int,
    opcode: str,
) -> bytes:
    """Build an AES-encrypted BLE frame (shared by query and lock commands)."""
    zero_padding = _zero_pad_hex(plaintext_hex)
    padded_hex = plaintext_hex + zero_padding
    padded_bytes = _hex_to_bytes(padded_hex)

    encrypted = _aes_ecb_encrypt(aes_key, padded_bytes)

    pad_byte_count = len(zero_padding) // 2
    suffix_byte = (pad_byte_count << 4) | (encrypt_type & 0x0F)

    total_len = len(encrypted) + 8
    frame = bytearray(total_len)
    frame[0:4] = HEAD_CMD
    frame[4] = total_len & 0xFF
    frame[5] = (total_len >> 8) & 0xFF
    frame[6 : 6 + len(encrypted)] = encrypted
    frame[6 + len(encrypted)] = suffix_byte
    frame[-1] = _crc8(bytes(frame[:-1]))

    return bytes(frame)


def _time_to_hex(tz_name: str | None = None) -> str:
    """Current time as BCD-to-hex string (yyMMddHHmmss).

    Equivalent to DataUtils.a(getSysformatTime(bb)).
    """
    import zoneinfo

    if tz_name:
        try:
            tz = zoneinfo.ZoneInfo(tz_name)
        except Exception:
            tz = None
    else:
        tz = None

    now = datetime.now(tz or timezone.utc)
    time_str = now.strftime("%y%m%d%H%M%S")

    result = []
    for i in range(0, len(time_str), 2):
        val = int(time_str[i : i + 2])
        result.append(f"{val:02x}")
    return "".join(result)


def build_query_status_command(
    master_code: str,
    uuid_hex: str,
    *,
    is_hub: bool = True,
    tz_name: str | None = None,
) -> bytes:
    """Build QueryLockStatusCmd BLE frame (opcode 1E, AES-encrypted).

    The lock responds with status data that includes the random number
    needed for subsequent lock/unlock commands.
    """
    enc_mc = _encrypt_master_code(master_code, uuid_hex)
    mc_len = len(enc_mc) // 2
    time_hex = _time_to_hex(tz_name)
    is_hub_str = "1" if is_hub else "0"

    hex_parts = [
        "1e",  # CMD_NEW_QUERY_LOCK_STATUS
        _pad_hex(str(mc_len)),
        enc_mc,
        time_hex,
        _pad_hex(is_hub_str),
    ]
    plaintext_hex = "".join(hex_parts)

    aes_key = derive_aes_key(master_code, uuid_hex)
    return _build_aes_frame(aes_key, plaintext_hex, encrypt_type=5, opcode="1e")


def _strip_aes_padding(hex_str: str) -> str:
    """Strip zero-padding from AES-decrypted response hex string.

    Equivalent to StringUtils.s() which reverses the string, finds the first
    non-zero hex char, and strips the trailing pad-count + zeros.
    """
    reversed_str = hex_str[::-1]
    for i, c in enumerate(reversed_str):
        if c != '0':
            pad_count = int(c, 16)
            pos = i
            if pos > 1 and pad_count >= 1 and pos == pad_count * 2:
                return hex_str[: len(hex_str) - (pos + 2)]
            return hex_str
    return hex_str


def parse_ble_response(
    frame: bytes,
    aes_key: bytes | None = None,
) -> dict:
    """Parse a BLE response frame, optionally AES-decrypting the payload.

    Response frame layout:
      [0:4]   HEAD_CMD (A1B2C3D4)
      [4:6]   total length (little-endian)
      [6:8]   cmd_type (e.g. 0A1E=success query, 0C22=error opcode 22)
      [8:-1]  data (encrypted for AES-capable locks)
      [-1]    CRC8

    Returns dict with opcode, is_error, error_code, decrypted_hex,
    random_number (if present in a query response).
    """
    if len(frame) < 8 or frame[:4] != HEAD_CMD:
        return {"error": "invalid frame", "raw": frame.hex()}

    total_len = frame[4] | (frame[5] << 8)

    cmd_type_hex = frame[6:8].hex() if len(frame) >= 8 else ""
    is_error = cmd_type_hex[:2] == "0c" if len(cmd_type_hex) >= 4 else False
    opcode = cmd_type_hex[2:4] if len(cmd_type_hex) >= 4 else ""

    result: dict = {
        "frame_hex": frame.hex(),
        "cmd_type": cmd_type_hex,
        "is_error": is_error,
        "opcode": opcode,
    }

    if is_error and len(frame) >= 9:
        result["error_code"] = frame[8]
        result["error_hex"] = f"0x{frame[8]:02x}"
        return result

    encrypted_data = frame[8:-1] if len(frame) > 9 else b""

    if aes_key and len(encrypted_data) >= 16 and len(encrypted_data) % 16 == 0:
        decrypted = _aes_ecb_decrypt(aes_key, encrypted_data)
        dec_hex = decrypted.hex()
        dec_hex_stripped = _strip_aes_padding(dec_hex)
        result["decrypted_hex"] = dec_hex_stripped
        result["decrypted_raw"] = dec_hex

        if len(dec_hex_stripped) >= 54:
            result["random_number"] = dec_hex_stripped[38:54]
        if len(dec_hex_stripped) >= 10:
            result["lock_status_byte"] = dec_hex_stripped[8:10]
            is_locked = ((int(dec_hex_stripped[8:10], 16) & 2) >> 1) == 1
            result["is_locked"] = is_locked

    return result


def build_lock_command(
    master_code: str,
    uuid_hex: str,
    *,
    lock: bool = True,
    pwd: str = "",
    pwd_id: int = 1,
    encrypt_type: int = 5,
    opcode: str = "22",
    via_hub: bool = True,
    use_aes: bool = True,
    random_number: str = "",
) -> bytes:
    """Build a BLE lock/unlock command frame.

    Args:
        master_code: The lock's master code (e.g. "10402776").
        uuid_hex: The lock's UUID as hex string (same as device ID).
        lock: True to lock, False to unlock.
        pwd: Host code / access PIN (e.g. "257596").
        pwd_id: Password ID (1 for host user).
        encrypt_type: 1=host non-AES, 5=host AES (default for new locks).
        opcode: "22" for new locks, "7" for legacy locks.
        via_hub: True when sending through hub.
        use_aes: True to use AES-ECB encryption.
        random_number: 16-char hex string from QueryLockStatusCmd response.
            Required for AES-encrypted commands on locks that need it.
    """
    enc_mc = _encrypt_master_code(master_code, uuid_hex)
    mc_len = len(enc_mc) // 2
    action = "2" if lock else "1"
    unlock_type = "2"

    hex_parts = [
        _pad_hex(opcode),
        _pad_hex(str(mc_len)),
        enc_mc,
        _pad_hex(unlock_type),
        _expand_pwd(pwd),
        _pad_hex(hex(pwd_id)[2:]),
        _pad_hex(action),
    ]
    if opcode == "22" and via_hub:
        hex_parts.append(_pad_hex("1"))

    if random_number:
        hex_parts.append(random_number)

    plaintext_hex = "".join(hex_parts)

    if use_aes:
        aes_key = derive_aes_key(master_code, uuid_hex)
        return _build_aes_frame(aes_key, plaintext_hex, encrypt_type, opcode)
    else:
        plaintext_bytes = _hex_to_bytes(plaintext_hex)
        enc_mc_bytes = _hex_to_bytes(enc_mc)
        xored = _xor_bytes(plaintext_bytes, enc_mc_bytes)

        total_len = len(xored) + 8
        frame = bytearray(total_len)
        frame[0:4] = HEAD_CMD
        frame[4] = total_len & 0xFF
        frame[5] = (total_len >> 8) & 0xFF
        frame[6 : 6 + len(xored)] = xored
        frame[6 + len(xored)] = encrypt_type
        frame[-1] = _crc8(bytes(frame[:-1]))

        return bytes(frame)


def build_lock_command_b64(
    master_code: str,
    uuid_hex: str,
    **kwargs,
) -> str:
    """Build a BLE lock/unlock command and return as base64 string."""
    return base64.b64encode(build_lock_command(master_code, uuid_hex, **kwargs)).decode("ascii")
