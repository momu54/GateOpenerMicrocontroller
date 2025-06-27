import wifi, board, digitalio, json, asyncio
import adafruit_hashlib as hashlib, circuitpython_hmac as hmac, adafruit_logging as logging
from adafruit_datetime import datetime, timedelta
from os import getenv
from time import sleep
from ipaddress import IPv4Address
from adafruit_httpserver import Server, Response, Request, Status
from socketpool import SocketPool
from microcontroller import reset, Pin
from binascii import b2a_base64
from collections import OrderedDict
from sys import stdout
from rtc import RTC
from adafruit_ntp import NTP

PRODUCTION = getenv("ENVIRONMENT", "") == "production"
logger = logging.getLogger()
logger.setLevel(logging.INFO if PRODUCTION else logging.DEBUG)
logger.addHandler(logging.FileHandler("/log/server.log", "a") if PRODUCTION else logging.StreamHandler(stdout))
assert logger.hasHandlers()

ssid = getenv("WIFI_SSID")
password = getenv("WIFI_PASSWORD")

if None in [ssid, password]:
    msg = "[x] WIFI_SSID and WIFI_PASSWORD must be set in settings.toml."
    logger.critical(msg)
    raise RuntimeError(msg)

ipv4 = IPv4Address(getenv("IP"))
netmask = IPv4Address(getenv("NETMASK"))
gateway = IPv4Address(getenv("GATEWAY"))
dns = IPv4Address(getenv("DNS"))
wifi.radio.set_ipv4_address(ipv4=ipv4, netmask=netmask, gateway=gateway, ipv4_dns=dns)
logger.debug("[v] IP configurated")

logger.debug(f"[.] Connecting to WiFi network {ssid}...")
try:
    wifi.radio.connect(ssid, password)
except TypeError:
    logger.exception("[x] Failed to connect to WiFi.")
    raise RuntimeError("[x] Failed to connect to WiFi.");
logger.debug("[v] Connected to WiFi!")
logger.debug(f"[-] IP Address: {wifi.radio.ipv4_address}")

led = digitalio.DigitalInOut(board.LED)
led.direction = digitalio.Direction.OUTPUT
gpios: dict[str, Pin] = {
    "OPEN": board.GP0,
    "CLOSE": board.GP15,
    "STOP": board.GP16
}

pool = SocketPool(wifi.radio)
server = Server(pool, debug=not PRODUCTION)
nonces: set[int] = set()

def SyncTime():
    ntp = NTP(pool, tz_offset=0).datetime
    RTC().datetime = ntp
    logger.debug("[v] Time synced.")

SyncTime()

hmacKey = getenv("HMAC_KEY", "DEFAULT_HMAC_KEY")
async def keepNonce(nonce: int):
    nonces.add(nonce)
    logger.debug(f"[.] Keeping nonce {nonce} for 60 seconds.")
    await asyncio.sleep(60)
    nonces.remove(nonce)
    logger.debug(f"[.] Removed nonce {nonce} after 60 seconds.")

async def ExecuteGPIOCommand(command: str):
    if command not in gpios.keys():
        logger.error(f"[x] Invalid GPIO command: {command}")
        return True

    logger.debug(command)
    gpio = digitalio.DigitalInOut(gpios[command])
    logger.debug(f"[.] Executing GPIO command: {command}")
    gpio.direction = digitalio.Direction.OUTPUT
    gpio.value = True
    led.value = False
    await asyncio.sleep(0.5)
    gpio.value = False
    led.value = True
    logger.debug(f"[v] GPIO command {command} executed successfully.")

@server.route(path="/", methods="POST")
def RequestHandler(request: Request):
    body: dict[str, str | dict[str, str]] = request.json() or {}
    value: dict[str, str | int] = OrderedDict(body["value"].items())

    if value["nonce"] in nonces:
        logger.info(f"[x] Nonce {value["nonce"]} already used.")
        return Response(request=request, content_type="application/json", body=json.dumps({
            "status": "failed",
            "message": "Nonce already used."
        }), status=Status(403, "Forbidden"))

    currentTime = datetime.now()
    expiry = datetime.fromisoformat(value["expiry"])
    if (expiry - currentTime) > timedelta(seconds=60):
        logger.info("[x] Expired signature received.")
        return Response(request=request, content_type="application/json", body=json.dumps({
            "status": "failed",
            "message": "Signature Expired."
        }))

    jsonValue = json.dumps(OrderedDict(sorted(value.items())), separators=(",", ":"))
    generatedSignatureBase64 = b2a_base64(hmac.new(hmacKey.encode(), msg=jsonValue, digestmod=hashlib.sha256).digest(), newline=False).decode()

    if generatedSignatureBase64 != body["signature"]:
        logger.info("[x] Invalid signature received.")
        return Response(request=request, content_type="application/json", body=json.dumps({
            "status": "failed",
            "message": "Invalid signature received."
        }), status=Status(403, "Forbidden"))

    logger.info(f"[.] Valid signature received for nonce {value["nonce"]}.")
    
    eventLoop = asyncio.get_event_loop()
    eventLoop.create_task(keepNonce(value["nonce"]))
    eventLoop.create_task(ExecuteGPIOCommand(value["action"]))

    return Response(request=request, content_type="text/plain", body=json.dumps({
        "status": "success",
        "message": "Signature verified successfully."
    }), status=Status(200, "OK"))

logger.debug("[.] Starting Server")
try:
    server.start(host=str(wifi.radio.ipv4_address), port=80)
    logger.info(f"[v] Server started successfully on http://{server.host}:{server.port}/")
    led.value = True
except OSError:
    sleep(5)
    logger.info("[.] Restarting server...")
    reset()

async def main():
    while True:
        try:
            server.poll()
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.exception(f"[x] Error occurred: {e}")
            reset()
        
asyncio.run(main())
