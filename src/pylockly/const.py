"""Constants extracted from the Lockly Android app (v3.3.0)."""

import base64

REST_BASE_URL = "https://apiserv03c.lockly.com/pgsmtlkv2/api/"

MQTT_BROKER_HOST = (
    "mqttuswest02-lb-001-b5ed8c5e37b3a497.elb.us-west-2.amazonaws.com"
)
MQTT_BROKER_PORT = 8883
MQTT_PUBLISH_TOPIC = "server"
MQTT_QOS = 2
MQTT_NAMESPACE = "com.lockly"

# Request/response type strings for MQTT header.name
REQ_LOCK_COMMAND = "lockCommandRequest"
REQ_HUB_COMMAND = "hubCommandRequest"
REQ_DEVICE_INFO = "deviceInfoRequest"
REQ_PING = "ping"
REQ_BIND_HUB = "bindHubAndLockRequest"
REQ_FIRMWARE_UPGRADE = "firmwareUpgradeRequest"
REQ_LOCK_LOG = "lockEventLogQueryRequest"

RESP_LOCK_COMMAND = "lockCommandResponse"
RESP_HUB_COMMAND = "hubCommandResponse"
RESP_DEVICE_STATE = "deviceStateCallback"
RESP_PONG = "pong"
RESP_DEVICE_INFO = "deviceInfoResponse"
RESP_FIRMWARE_PROGRESS = "firmwareUpgradeProgress"
RESP_FIRMWARE_FAILURE = "firmwareUpgradeFailure"
RESP_LOCK_LOG = "lockEventLogQueryResponse"
RESP_EXCEPTION = "exception"

# Client metadata sent on every REST request (mimics Android app)
CLIENT_OS = "android"
CLIENT_VER = "2.3.7"
CLIENT_VERSION_NAME = "237"
CLIENT_COUNTRY = "AU"
CLIENT_LOCALE = "EN"

MQTT_RESPONSE_TIMEOUT = 30.0

# RSA keys for anonymous encryption (from lockly_api Dart client)
# Public key: X.509 SubjectPublicKeyInfo, 1024-bit RSA
_RSA_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZtiijnvRo5EEI0n2I7shxljMX"
    "b7mZ/FpjuS98MHGWuYYUrsiJQVgfPn29lmI/MDkhVc7oVTsg5BIyC0TUpZKTgxyF"
    "DZw08AdWKe9JZvzyGB00AGkRxcem2J64xJJ04o9FW6PDLF0gSvblZAvUdHU1YyfB"
    "7DgJhikP7lPrFNdGwwIDAQAB"
)

# Private key: PKCS#8, used to decrypt server responses
_RSA_PRIVATE_KEY_B64 = (
    "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMBZug0p9CRIsZI+"
    "o3rMj1dlKt7AE52Ql44dSgVvaTVZ3ZWB2vRpvA80cF/QQXVbODgaU3xD0ZTkeGY6"
    "EP3lQaxLwGbQC1xrfLl4rVJPBt2qk0EtSQt729rOYBzMJSp0r5fPMmVDPogp3neM"
    "lFhP2xFlkp+yy+hsbkvXmsT9kpZjAgMBAAECgYAy0cIBJlt1lqsrq1b/47nfakA4"
    "V+EW2RPhnUVoSDYwvUx46rURrDnefolOFzSkL/SbhgEWrMhboT1aLO8+VWrTCF3B"
    "L2BPK0+G0QGYh8l56qk0dyoJiAz6Qus4OSlypNO01VIZGhNfayYlPjVlrZtDRTZF"
    "1kPbnUjcUwEKsrHXcQJBAOZbj4zopmYTfB7xFsbyP/K7nMOREjANLilie1Fkl8RZ8"
    "xSRwdz6s7r1Vx3JuUZbwyyNMG27NO+tZgdvF0u3pskCQQDVwxYUyuF+iIH9Ia2qQ"
    "1c1Al5fIBBUY8o7BT4tviLpQEjL2lZeJBvlRRzCyiZZISR+KXq8Id4+OKVpix6Fo"
    "C3LAkB9z0niannezAuBFqka9NmKJ38hrEyjo78vaRLyzB67ZWkGNekMWHvqwu3WXg"
    "Lrc1hwL5hghdsOf8R2kOzHNMFJAkA7xh+olMrVbSqcNAyx7b63DgCBrR+j2Xu1YV"
    "PvyplMjDNO/bDlBkfepqLSPWDXz5K6zLKLZRUWZRSsHMDeMNpdAkB1CAvpgzVt/O"
    "YbGvUDDK9VFbKtprN0hyFxuaX/pYaQL8hz7l+wkSvAd6lQgNlW5qLfYog06XUexr"
    "OFRvMjIhMm"
)

RSA_PUBLIC_KEY_DER = base64.b64decode(_RSA_PUBLIC_KEY_B64)
RSA_PRIVATE_KEY_DER = base64.b64decode(_RSA_PRIVATE_KEY_B64)
