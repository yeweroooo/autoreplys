import asyncio
import base64
import json
import logging
import os
import random
import re
import sys
import time
import zlib
from pathlib import Path
from typing import Optional, Dict, Any, Callable, List
from datetime import datetime, timezone
from hashlib import md5
from collections import deque

try:
    import termios
    import tty
except ImportError:
    termios = None
    tty = None

try:
    from curl_cffi import requests
    import websockets
    from colorama import Fore, Style, init as colorama_init
except ImportError as e:
    print(f"Missing dependencies. Install: pip install curl_cffi websockets colorama")
    sys.exit(1)

colorama_init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
LOGGER = logging.getLogger("autoreply")

CONFIG_PATH = Path("config.json")
REPLIED_FILE = Path("replied.txt")
ERROR_FILE = Path("error.txt")
SESSION_CACHE = Path(".session_cache.json")

_replied_lock = asyncio.Lock()
_replied_channels: set[int] = set()
_replying_channels: set[int] = set()
_error_lock = asyncio.Lock()
_errored_channels: set[int] = set()
_processing_lock = asyncio.Lock()
_last_request_time: Dict[str, float] = {}


class DeviceGenerator:
    ANDROID_DEVICES = {
        "samsung": {
            "models": ["SM-S928B", "SM-S926B", "SM-S918B", "SM-G998B", "SM-G991B", "SM-G996B", "SM-G973F", "SM-G975F"],
            "brands": ["samsung"],
            "cpus": ["Exynos 2400", "Exynos 2200", "Snapdragon 8 Gen 3", "Snapdragon 8 Gen 2"]
        },
        "Google": {
            "models": ["Pixel 9 Pro", "Pixel 8 Pro", "Pixel 8", "Pixel 7 Pro", "Pixel 7", "Pixel 6 Pro", "Pixel 6"],
            "brands": ["google"],
            "cpus": ["Tensor G4", "Tensor G3", "Tensor G2"]
        },
        "OnePlus": {
            "models": ["CPH2581", "CPH2451", "CPH2417", "CPH2399", "LE2123", "LE2121", "GM1917"],
            "brands": ["oneplus", "oppo"],
            "cpus": ["Snapdragon 8 Gen 3", "Snapdragon 8 Gen 2", "Snapdragon 8 Gen 1"]
        },
        "Xiaomi": {
            "models": ["23127PN0CC", "23078PND5G", "2211133G", "2201123G", "2107113SG", "M2102J20SG"],
            "brands": ["xiaomi", "redmi"],
            "cpus": ["Snapdragon 8 Gen 3", "Snapdragon 8 Gen 2", "Dimensity 9200+"]
        },
        "OPPO": {
            "models": ["CPH2591", "CPH2581", "CPH2505", "CPH2473", "CPH2499", "CPH2219"],
            "brands": ["oppo"],
            "cpus": ["Snapdragon 8 Gen 3", "Snapdragon 8 Gen 2", "Dimensity 9200"]
        }
    }
    
    OS_VERSIONS = ["34", "33", "32", "31"]
    
    @classmethod
    def generate(cls) -> Dict[str, str]:
        manufacturer = random.choice(list(cls.ANDROID_DEVICES.keys()))
        config = cls.ANDROID_DEVICES[manufacturer]
        model = random.choice(config["models"])
        brand = random.choice(config["brands"])
        cpu = random.choice(config["cpus"])
        os_version = random.choice(cls.OS_VERSIONS)
        
        device_hash = md5(f"{manufacturer}{model}{brand}{time.time()}".encode()).hexdigest()[:16]
        
        return {
            "manufacturer": manufacturer,
            "model": model,
            "brand": brand,
            "cpu": cpu,
            "os_version": os_version,
            "device_hash": device_hash
        }


class BuildNumberFetcher:
    CACHE_DURATION = 3600
    _cached_build = None
    _cache_time = 0
    
    @classmethod
    def get_build_number(cls) -> int:
        if cls._cached_build and (time.time() - cls._cache_time) < cls.CACHE_DURATION:
            return cls._cached_build
        
        try:
            session = requests.Session()
            chrome_versions = ["chrome136", "chrome133a", "chrome131", "chrome124"]
            impersonate = random.choice(chrome_versions)
            
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
                "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="131"',
                "Sec-Ch-Ua-Mobile": "?1",
                "Sec-Ch-Ua-Platform": '"Android"',
            }
            
            response = session.get(
                "https://discord.com/app",
                headers=headers,
                impersonate=impersonate,
                timeout=15
            )
            
            pattern = r'"buildNumber"\s*:\s*(\d+)'
            match = re.search(pattern, response.text)
            
            if match:
                build_num = int(match.group(1))
                cls._cached_build = build_num
                cls._cache_time = time.time()
                return build_num
            
            alt_pattern = r'Build Number:\s*(\d+)'
            alt_match = re.search(alt_pattern, response.text)
            
            if alt_match:
                build_num = int(alt_match.group(1))
                cls._cached_build = build_num
                cls._cache_time = time.time()
                return build_num
                
        except:
            pass
        
        fallback = random.randint(338000, 345000)
        cls._cached_build = fallback
        cls._cache_time = time.time()
        return fallback


class DiscordHTTPClient:
    BASE_URL = "https://discord.com/api/v9"
    
    ANDROID_USER_AGENTS = [
        "Discord-Android/245.13 - rn (24513); RNA",
        "Discord-Android/244.12 - rn (24412); RNA", 
        "Discord-Android/243.11 - rn (24311); RNA",
        "Discord-Android/242.10 - rn (24210); RNA"
    ]
    
    def __init__(self, token: str):
        self.token = token
        self.session = requests.Session()
        
        chrome_android_versions = ["chrome136", "chrome133a", "chrome131", "chrome124", "chrome120"]
        self.impersonate = random.choice(chrome_android_versions)
        
        self.device_info = DeviceGenerator.generate()
        self.build_number = BuildNumberFetcher.get_build_number()
        self.fingerprint = None
        self.session_id = None
        self._rate_limit_remaining = {}
        self._request_history = deque(maxlen=100)
        
    def _generate_device_id(self) -> str:
        import uuid
        return str(uuid.uuid4())
    
    def _get_timezone_offset(self) -> str:
        now = datetime.now()
        offset = now.astimezone().strftime('%z')
        return f"{offset[:3]}:{offset[3:]}"
    
    def _get_client_event_source(self) -> Optional[str]:
        sources = [None, "direct_messages", "recent_mentions"]
        return random.choice(sources)
    
    def _get_headers(self, content_type: str = "application/json") -> Dict[str, str]:
        user_agent = random.choice(self.ANDROID_USER_AGENTS)
        
        headers = {
            "Authorization": self.token,
            "User-Agent": user_agent,
            "X-Discord-Locale": "en-US",
            "X-Discord-Timezone": self._get_timezone_offset(),
            "X-Debug-Options": "bugReporterEnabled",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": content_type,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Origin": "https://discord.com",
            "X-Super-Properties": self._get_super_properties(),
            "Referer": "https://discord.com/channels/@me",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Ch-Ua": f'"Not_A Brand";v="8", "Chromium";v="{random.randint(120, 136)}"',
            "Sec-Ch-Ua-Mobile": "?1",
            "Sec-Ch-Ua-Platform": '"Android"',
        }
        
        if self.fingerprint:
            headers["X-Fingerprint"] = self.fingerprint
        
        return headers
    
    def _get_super_properties(self) -> str:
        props = {
            "os": "Android",
            "browser": "Discord Android",
            "device": self.device_info["model"],
            "system_locale": "en-US",
            "client_version": str(self.build_number),
            "release_channel": "googleRelease",
            "device_vendor_id": self.device_info["device_hash"],
            "browser_user_agent": "",
            "browser_version": "",
            "os_version": self.device_info["os_version"],
            "manufacturer": self.device_info["manufacturer"],
            "model": self.device_info["model"],
            "brand": self.device_info["brand"],
            "client_build_number": self.build_number,
            "native_build_number": random.randint(35000, 38000),
            "design_id": 0,
            "client_performance_cpu": self.device_info["cpu"],
            "client_performance_memory": random.choice([4, 6, 8, 12, 16]) * 1024
        }
        
        client_event_source = self._get_client_event_source()
        if client_event_source:
            props["client_event_source"] = client_event_source
        
        json_props = json.dumps(props, separators=(',', ':'))
        return base64.b64encode(json_props.encode()).decode()
    
    def _should_wait_rate_limit(self, endpoint: str) -> float:
        key = endpoint.split('?')[0]
        last_time = _last_request_time.get(key, 0)
        
        if "/typing" in endpoint:
            min_interval = random.uniform(0.5, 1.0)
        elif "/messages" in endpoint and "GET" not in str(endpoint):
            min_interval = random.uniform(1.2, 2.0)
        else:
            min_interval = random.uniform(0.8, 1.5)
        
        elapsed = time.time() - last_time
        
        if elapsed < min_interval:
            return min_interval - elapsed
        return 0
    
    def _update_rate_limit(self, endpoint: str):
        key = endpoint.split('?')[0]
        _last_request_time[key] = time.time()
        self._request_history.append({
            "endpoint": key,
            "timestamp": time.time()
        })
    
    def request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        url = f"{self.BASE_URL}{endpoint}"
        
        wait_time = self._should_wait_rate_limit(endpoint)
        if wait_time > 0:
            time.sleep(wait_time)
        
        headers = self._get_headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        
        kwargs["impersonate"] = self.impersonate
        kwargs["headers"] = headers
        kwargs["timeout"] = 30
        
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                response = self.session.request(method, url, **kwargs)
                self._update_rate_limit(endpoint)
                
                if response.status_code == 429:
                    retry_after = response.json().get("retry_after", 5)
                    jitter = random.uniform(0.5, 1.5)
                    time.sleep(retry_after + jitter)
                    retry_count += 1
                    continue
                
                if response.status_code >= 400:
                    return None
                    
                if response.text:
                    return response.json()
                return {}
                
            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    return None
                time.sleep(random.uniform(1, 3))
        
        return None
    
    def get(self, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        return self.request("GET", endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        return self.request("POST", endpoint, **kwargs)
    
    def patch(self, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        return self.request("PATCH", endpoint, **kwargs)
    
    def get_fingerprint(self) -> bool:
        result = self.post("/auth/fingerprint")
        if result and "fingerprint" in result:
            self.fingerprint = result["fingerprint"]
            return True
        return False
    
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        return self.get("/users/@me")
    
    def get_gateway_url(self) -> Optional[str]:
        result = self.get("/gateway")
        if result and "url" in result:
            return result["url"]
        return None
    
    def get_dm_channels(self) -> Optional[list]:
        return self.get("/users/@me/channels")
    
    def send_message(self, channel_id: int, content: str) -> Optional[Dict[str, Any]]:
        payload = {
            "content": content,
            "nonce": str(random.randint(10**17, 10**18 - 1)),
            "tts": False
        }
        return self.post(f"/channels/{channel_id}/messages", json=payload)
    
    def trigger_typing(self, channel_id: int) -> bool:
        result = self.post(f"/channels/{channel_id}/typing")
        return result is not None
    
    def update_presence(self, status: str = "online") -> Optional[Dict[str, Any]]:
        payload = {"status": status}
        return self.patch("/users/@me/settings", json=payload)
    
    def get_channel_messages(self, channel_id: int, limit: int = 1) -> Optional[list]:
        return self.get(f"/channels/{channel_id}/messages", params={"limit": limit})
    
    def acknowledge_message(self, channel_id: int, message_id: int) -> bool:
        result = self.post(f"/channels/{channel_id}/messages/{message_id}/ack", json={"token": None})
        return result is not None


class DiscordGateway:
    GATEWAY_URL_TEMPLATE = "wss://{}/?v=9&encoding=json&compress=zlib-stream"
    
    DISPATCH = 0
    HEARTBEAT = 1
    IDENTIFY = 2
    PRESENCE_UPDATE = 3
    VOICE_STATE_UPDATE = 4
    RESUME = 6
    RECONNECT = 7
    REQUEST_GUILD_MEMBERS = 8
    INVALID_SESSION = 9
    HELLO = 10
    HEARTBEAT_ACK = 11
    
    CLOSE_CODES = {
        4000: "Unknown error",
        4001: "Unknown opcode",
        4002: "Decode error",
        4003: "Not authenticated",
        4004: "Authentication failed",
        4005: "Already authenticated",
        4007: "Invalid sequence",
        4008: "Rate limited",
        4009: "Session timed out",
        4010: "Invalid shard",
        4011: "Sharding required",
        4012: "Invalid API version",
        4013: "Invalid intent(s)",
        4014: "Disallowed intent(s)",
    }
    
    def __init__(self, token: str, http_client):
        self.token = token
        self.http_client = http_client
        self.ws = None
        self.session_id = None
        self.sequence = None
        self.resume_gateway_url = None
        self.heartbeat_interval = None
        self.heartbeat_task = None
        self.user_id = None
        self.username = None
        self.inflator = zlib.decompressobj()
        self.handlers: Dict[str, list] = {}
        self.connected = False
        self.ready = False
        self._last_heartbeat = 0
        self._last_heartbeat_ack = 0
        self._missed_heartbeats = 0
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 10
        self._gateway_url = None
        self._cache_session()
        
    def _cache_session(self):
        if SESSION_CACHE.exists():
            try:
                with SESSION_CACHE.open('r') as f:
                    data = json.load(f)
                    self.session_id = data.get('session_id')
                    self.sequence = data.get('sequence')
                    self.resume_gateway_url = data.get('resume_gateway_url')
            except:
                pass
    
    def _save_session(self):
        try:
            with SESSION_CACHE.open('w') as f:
                json.dump({
                    'session_id': self.session_id,
                    'sequence': self.sequence,
                    'resume_gateway_url': self.resume_gateway_url,
                    'timestamp': time.time()
                }, f)
        except:
            pass
    
    def _is_connected(self) -> bool:
        return self.connected and self.ws is not None
    
    def on(self, event_name: str):
        def decorator(func: Callable):
            if event_name not in self.handlers:
                self.handlers[event_name] = []
            self.handlers[event_name].append(func)
            return func
        return decorator
    
    async def emit(self, event_name: str, *args, **kwargs):
        if event_name in self.handlers:
            for handler in self.handlers[event_name]:
                try:
                    await handler(*args, **kwargs)
                except Exception:
                    pass
    
    def _get_identify_payload(self) -> Dict[str, Any]:
        return {
            "op": self.IDENTIFY,
            "d": {
                "token": self.token,
                "capabilities": 16381,
                "properties": {
                    "os": "Android",
                    "browser": "Discord Android",
                    "device": self.http_client.device_info["model"],
                    "system_locale": "en-US",
                    "client_version": str(self.http_client.build_number),
                    "release_channel": "googleRelease",
                    "device_vendor_id": self.http_client.device_info["device_hash"],
                    "browser_user_agent": "",
                    "browser_version": "",
                    "os_version": self.http_client.device_info["os_version"],
                    "manufacturer": self.http_client.device_info["manufacturer"],
                    "model": self.http_client.device_info["model"],
                    "brand": self.http_client.device_info["brand"],
                    "client_build_number": self.http_client.build_number,
                    "native_build_number": random.randint(35000, 38000),
                    "design_id": 0
                },
                "presence": {
                    "status": "online",
                    "since": 0,
                    "activities": [],
                    "afk": False
                },
                "compress": True,
                "client_state": {
                    "guild_versions": {},
                    "highest_last_message_id": "0",
                    "read_state_version": 0,
                    "user_guild_settings_version": -1,
                    "user_settings_version": -1,
                    "private_channels_version": "0",
                    "api_code_version": 0
                }
            }
        }
    
    def _get_resume_payload(self) -> Dict[str, Any]:
        return {
            "op": self.RESUME,
            "d": {
                "token": self.token,
                "session_id": self.session_id,
                "seq": self.sequence
            }
        }
    
    async def _send_heartbeat(self):
        if self._is_connected():
            try:
                payload = {
                    "op": self.HEARTBEAT,
                    "d": self.sequence
                }
                await self.ws.send(json.dumps(payload))
                self._last_heartbeat = time.time()
            except:
                pass
    
    async def _heartbeat_loop(self):
        jitter = random.uniform(0, 1)
        await asyncio.sleep(self.heartbeat_interval / 1000 * jitter)
        
        while self._is_connected():
            try:
                time_since_ack = time.time() - self._last_heartbeat_ack if self._last_heartbeat_ack > 0 else 0
                
                if time_since_ack > 45:
                    self._missed_heartbeats += 1
                    
                    if self._missed_heartbeats >= 3:
                        await self.reconnect()
                        break
                else:
                    self._missed_heartbeats = 0
                    
                await self._send_heartbeat()
                await asyncio.sleep(self.heartbeat_interval / 1000)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(self.heartbeat_interval / 1000)
    
    async def update_presence(self, status: str = "online", activities: list = None):
        if not self._is_connected():
            return
        
        if activities is None:
            activities = []
        
        payload = {
            "op": self.PRESENCE_UPDATE,
            "d": {
                "since": int(time.time() * 1000) if status != "online" else 0,
                "activities": activities,
                "status": status,
                "afk": False
            }
        }
        
        try:
            await self.ws.send(json.dumps(payload))
            await asyncio.to_thread(self.http_client.update_presence, status)
        except:
            pass
    
    def _decompress_message(self, data: bytes) -> Optional[str]:
        try:
            buffer = self.inflator.decompress(data)
            
            if len(data) >= 4 and data[-4:] == b'\x00\x00\xff\xff':
                buffer += self.inflator.flush(zlib.Z_SYNC_FLUSH)
                
                if buffer:
                    return buffer.decode('utf-8')
            
            return None
        except:
            return None
    
    async def _handle_dispatch(self, event_type: str, data: Dict[str, Any]):
        if event_type == "READY":
            self.session_id = data.get("session_id")
            self.resume_gateway_url = data.get("resume_gateway_url")
            self.user_id = data.get("user", {}).get("id")
            self.username = data.get("user", {}).get("username")
            self.ready = True
            self._reconnect_attempts = 0
            self._save_session()
            await self.emit("ready", data)
            
        elif event_type == "MESSAGE_CREATE":
            await self.emit("message", data)
            
        elif event_type == "RESUMED":
            self.ready = True
            self._reconnect_attempts = 0
            await self.emit("resumed")
    
    async def _handle_message(self, message: str):
        try:
            data = json.loads(message)
            op = data.get("op")
            d = data.get("d")
            s = data.get("s")
            t = data.get("t")
            
            if s is not None:
                self.sequence = s
                self._save_session()
            
            if op == self.HELLO:
                self.heartbeat_interval = d.get("heartbeat_interval", 41250)
                self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
                
                if self.session_id and self.sequence is not None:
                    resume_payload = self._get_resume_payload()
                    await self.ws.send(json.dumps(resume_payload))
                else:
                    identify_payload = self._get_identify_payload()
                    await self.ws.send(json.dumps(identify_payload))
                
            elif op == self.HEARTBEAT_ACK:
                self._last_heartbeat_ack = time.time()
                self._missed_heartbeats = 0
                
            elif op == self.RECONNECT:
                await self.reconnect()
                
            elif op == self.INVALID_SESSION:
                resumable = d if isinstance(d, bool) else False
                
                if not resumable:
                    self.session_id = None
                    self.sequence = None
                    self.resume_gateway_url = None
                    self._save_session()
                
                await asyncio.sleep(random.uniform(1, 5))
                await self.reconnect()
                    
            elif op == self.DISPATCH:
                await self._handle_dispatch(t, d)
                
        except:
            pass
    
    async def connect(self):
        while self._reconnect_attempts < self._max_reconnect_attempts:
            try:
                if not self._gateway_url:
                    gateway_url = await asyncio.to_thread(self.http_client.get_gateway_url)
                    if gateway_url:
                        self._gateway_url = gateway_url.replace("wss://", "")
                
                if self.resume_gateway_url and self.session_id:
                    gateway_domain = self.resume_gateway_url.replace("wss://", "")
                    ws_url = self.GATEWAY_URL_TEMPLATE.format(gateway_domain)
                elif self._gateway_url:
                    ws_url = self.GATEWAY_URL_TEMPLATE.format(self._gateway_url)
                else:
                    ws_url = self.GATEWAY_URL_TEMPLATE.format("gateway.discord.gg")
                
                self.ws = await websockets.connect(
                    ws_url,
                    max_size=None,
                    compression=None,
                    ping_interval=None,
                    ping_timeout=None,
                    close_timeout=10
                )
                
                self.connected = True
                self._reconnect_attempts = 0
                
                try:
                    async for message in self.ws:
                        if isinstance(message, bytes):
                            decompressed = self._decompress_message(message)
                            if decompressed:
                                await self._handle_message(decompressed)
                        else:
                            await self._handle_message(message)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
                        
            except websockets.exceptions.ConnectionClosed as e:
                self.connected = False
                self.ready = False
                await self.emit("disconnect")
                
                close_code = e.code if hasattr(e, 'code') else None
                
                if close_code in [4004, 4010, 4011, 4012, 4013, 4014]:
                    return
                
                backoff = min(2 ** self._reconnect_attempts, 60)
                jitter = random.uniform(0, backoff * 0.3)
                await asyncio.sleep(backoff + jitter)
                
                self._reconnect_attempts += 1
                continue
                
            except asyncio.CancelledError:
                self.connected = False
                self.ready = False
                return
                
            except Exception:
                self.connected = False
                self.ready = False
                
                backoff = min(2 ** self._reconnect_attempts, 60)
                jitter = random.uniform(0, backoff * 0.3)
                await asyncio.sleep(backoff + jitter)
                
                self._reconnect_attempts += 1
                continue
        
        self.connected = False
        self.ready = False
    
    async def reconnect(self):
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
            
        self.connected = False
        self.ready = False
        
        if self.ws:
            try:
                await self.ws.close()
            except:
                pass
        
        self.ws = None
        self.inflator = zlib.decompressobj()
        
        backoff = min(2 ** self._reconnect_attempts, 60)
        jitter = random.uniform(0, backoff * 0.3)
        await asyncio.sleep(backoff + jitter)
        
        self._reconnect_attempts += 1
    
    async def close(self):
        self.connected = False
        self.ready = False
        
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self.ws:
            try:
                await self.ws.close()
            except:
                pass
        
        self.ws = None


class DiscordClient:
    def __init__(self, token: str):
        self.token = token
        self.http = DiscordHTTPClient(token)
        self.gateway = DiscordGateway(token, self.http)
        self.user = None
        self.dm_channels = []
        self._event_handlers: Dict[str, list] = {}
        self._running = False
        self._keep_alive_task = None
    
    def event(self, func: Callable):
        event_name = func.__name__
        if event_name.startswith("on_"):
            event_name = event_name[3:]
        
        if event_name not in self._event_handlers:
            self._event_handlers[event_name] = []
        self._event_handlers[event_name].append(func)
        
        self.gateway.on(event_name)(func)
        
        return func
    
    async def _setup_ready_handler(self):
        @self.gateway.on("ready")
        async def on_ready_internal(data):
            self.http.get_fingerprint()
            self.user = await asyncio.to_thread(self.http.get_user_info)
            
            dm_channels = await asyncio.to_thread(self.http.get_dm_channels)
            if dm_channels:
                self.dm_channels = dm_channels
            
            if "ready" in self._event_handlers:
                for handler in self._event_handlers["ready"]:
                    await handler()
    
    async def _setup_message_handler(self):
        @self.gateway.on("message")
        async def on_message_internal(data):
            message = Message(data, self)
            
            if "message" in self._event_handlers:
                for handler in self._event_handlers["message"]:
                    await handler(message)
    
    async def _keep_alive_loop(self):
        while self._running:
            try:
                await asyncio.sleep(30)
                
                if not self.gateway.connected or not self.gateway.ready:
                    log_process("Gateway not connected. Checking status...")
                    await asyncio.sleep(5)
                    
                    if not self.gateway.connected and self.gateway._reconnect_attempts < self.gateway._max_reconnect_attempts:
                        log_process("Attempting manual reconnection...")
                        await self.gateway.reconnect()
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(10)
    
    async def start(self):
        self._running = True
        await self._setup_ready_handler()
        await self._setup_message_handler()
        
        self._keep_alive_task = asyncio.create_task(self._keep_alive_loop())
        
        try:
            await self.gateway.connect()
        except Exception:
            pass
        finally:
            self._running = False
            if self._keep_alive_task:
                self._keep_alive_task.cancel()
                try:
                    await self._keep_alive_task
                except asyncio.CancelledError:
                    pass
    
    async def change_presence(self, status: str = "online"):
        await self.gateway.update_presence(status)
    
    async def send_message(self, channel_id: int, content: str, simulate_typing: bool = True) -> Optional[Dict[str, Any]]:
        if simulate_typing:
            await asyncio.to_thread(self.http.trigger_typing, channel_id)
            
            typing_time = len(content) * random.uniform(0.03, 0.08)
            typing_time = min(typing_time, random.uniform(2.5, 4.5))
            await asyncio.sleep(typing_time)
        
        return await asyncio.to_thread(self.http.send_message, channel_id, content)
    
    async def get_dm_channels(self) -> list:
        channels = await asyncio.to_thread(self.http.get_dm_channels)
        if channels:
            self.dm_channels = channels
            return channels
        return []
    
    async def get_channel_messages(self, channel_id: int, limit: int = 1) -> Optional[list]:
        return await asyncio.to_thread(self.http.get_channel_messages, channel_id, limit)
    
    def run(self):
        try:
            asyncio.run(self.start())
        except KeyboardInterrupt:
            pass
    
    async def close(self):
        self._running = False
        
        if self._keep_alive_task:
            self._keep_alive_task.cancel()
            try:
                await self._keep_alive_task
            except asyncio.CancelledError:
                pass
        
        try:
            await self.gateway.close()
        except:
            pass


class Message:
    def __init__(self, data: Dict[str, Any], client: DiscordClient):
        self.data = data
        self.client = client
        
        self.id = int(data.get("id", 0))
        self.content = data.get("content", "")
        self.channel_id = int(data.get("channel_id", 0))
        self.guild_id = data.get("guild_id")
        self.timestamp = data.get("timestamp")
        
        author_data = data.get("author", {})
        self.author = User(author_data)
        
        self.channel = DMChannel(self.channel_id, self.client)
        self.guild = None if not self.guild_id else self.guild_id
    
    async def reply(self, content: str):
        return await self.client.send_message(self.channel_id, content)


class User:
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.id = int(data.get("id", 0))
        self.username = data.get("username", "")
        self.discriminator = data.get("discriminator", "0")
        self.global_name = data.get("global_name")
        self.bot = data.get("bot", False)
        self.avatar = data.get("avatar")
    
    def __str__(self):
        if self.global_name:
            return self.global_name
        if self.discriminator and self.discriminator != "0":
            return f"{self.username}#{self.discriminator}"
        return self.username


class DMChannel:
    def __init__(self, channel_id: int, client: DiscordClient):
        self.id = channel_id
        self.client = client
        self.recipient = None
    
    async def send(self, content: str):
        return await self.client.send_message(self.id, content)
    
    async def history(self, limit: int = 100):
        return await self.client.get_channel_messages(self.id, limit)


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _load_config() -> dict[str, str]:
    default = {"token": "", "presence": "", "message": ""}
    if not CONFIG_PATH.exists():
        return default.copy()
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("config malformed")
            return {
                "token": str(data.get("token", "")),
                "presence": str(data.get("presence", "")),
                "message": str(data.get("message", "")),
            }
    except Exception:
        return default.copy()


def _save_config(config: dict[str, str]) -> None:
    try:
        CONFIG_PATH.write_text(
            json.dumps(
                {
                    "token": config.get("token", ""),
                    "presence": config.get("presence", ""),
                    "message": config.get("message", ""),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError:
        pass


def _load_id_file(file_path: Path, target: set[int], label: str) -> None:
    target.clear()
    try:
        file_path.touch(exist_ok=True)
    except OSError as exc:
        log_error(f"Unable to create or touch {file_path.name}: {exc}")
        return

    try:
        with file_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    target.add(int(line))
                except ValueError:
                    pass
    except OSError:
        pass


async def _record_id(user_id: int, *, file_path: Path, target: set[int], lock: asyncio.Lock) -> None:
    async with lock:
        if user_id in target:
            return

        target.add(user_id)
        try:
            with file_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{user_id}\n")
        except OSError:
            pass


async def _mark_replying(channel_id: int) -> bool:
    async with _replied_lock:
        if channel_id in _replied_channels or channel_id in _replying_channels:
            return False
        _replying_channels.add(channel_id)
        return True


async def _clear_replying(channel_id: int) -> None:
    async with _replied_lock:
        _replying_channels.discard(channel_id)


async def _record_reply(channel_id: int) -> None:
    async with _replied_lock:
        _replying_channels.discard(channel_id)
        if channel_id in _replied_channels:
            return

        _replied_channels.add(channel_id)
        try:
            with REPLIED_FILE.open("a", encoding="utf-8") as handle:
                handle.write(f"{channel_id}\n")
        except OSError:
            pass


async def _record_error(channel_id: int) -> None:
    await _record_id(channel_id, file_path=ERROR_FILE, target=_errored_channels, lock=_error_lock)


def _log_with_color(color: str, message: str, *, level: str) -> None:
    if level == "error":
        LOGGER.error("%s%s%s", color, message, Style.RESET_ALL)
    else:
        LOGGER.info("%s%s%s", color, message, Style.RESET_ALL)


def log_process(message: str) -> None:
    _log_with_color(Fore.YELLOW, message, level="process")


def log_success(message: str) -> None:
    _log_with_color(Fore.GREEN, message, level="success")


def log_error(message: str) -> None:
    _log_with_color(Fore.RED, message, level="error")


def validate_token_http(token: str) -> bool:
    try:
        client = DiscordHTTPClient(token)
        client.get_fingerprint()
        user = client.get_user_info()
        return user is not None
    except:
        return False


async def _process_dm_channels(client: DiscordClient, message_text: str) -> None:
    if _processing_lock.locked():
        return

    async with _processing_lock:
        try:
            dm_channels = await client.get_dm_channels()
            if not dm_channels:
                return

            for channel_data in dm_channels:
                channel_id = int(channel_data.get("id", 0))
                if not channel_id:
                    continue

                if channel_id in _replied_channels or channel_id in _errored_channels:
                    continue

                recipient = channel_data.get("recipients", [{}])[0] if channel_data.get("recipients") else {}
                if recipient.get("bot", False):
                    log_process(f"Skipping bot DM channel {channel_id}")
                    await _record_error(channel_id)
                    continue

                if not await _mark_replying(channel_id):
                    continue

                try:
                    messages = await client.get_channel_messages(channel_id, limit=1)
                    
                    if not messages:
                        await _clear_replying(channel_id)
                        continue

                    last_message = messages[0]
                    
                    if client.user and int(last_message.get("author", {}).get("id", 0)) == int(client.user.get("id", 0)):
                        await _clear_replying(channel_id)
                        continue

                    recipient_name = recipient.get("global_name") or recipient.get("username", "Unknown")
                    log_process(f"Sending autoreply to {recipient_name} (Channel: {channel_id})")
                    
                    await asyncio.sleep(random.uniform(1.5, 3.5))
                    
                    result = await client.send_message(channel_id, message_text, simulate_typing=True)
                    
                    if result:
                        log_success(f"Autoreply sent to {recipient_name}")
                        await _record_reply(channel_id)
                    else:
                        log_error(f"Failed to send reply to {recipient_name}")
                        await _record_error(channel_id)
                        
                except Exception:
                    await _clear_replying(channel_id)
                    await _record_error(channel_id)

        except Exception:
            pass


def display_menu(config: dict[str, str]) -> None:
    clear_screen()

    token_status = Fore.GREEN + "Set" if config.get("token") else Fore.RED + "Not Set"
    presence_value = config.get("presence") or "Not Set"
    presence_status = Fore.CYAN + presence_value.lower() if config.get("presence") else Fore.RED + "Not Set"
    message_status = Fore.GREEN + "Set" if config.get("message") else Fore.RED + "Not Set"

    print(Fore.MAGENTA + Style.BRIGHT + "Fuhuu Simple Autoreply Discord" + Style.RESET_ALL)
    print(Fore.WHITE + "Status :" + Style.RESET_ALL)
    print(f"{Fore.WHITE}Token : {token_status}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Message : {message_status}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Presence : {presence_status}{Style.RESET_ALL}")
    print()
    print(Fore.CYAN + "1. Input The Token" + Style.RESET_ALL)
    print(Fore.CYAN + "2. Set Message" + Style.RESET_ALL)
    print(Fore.CYAN + "3. Set Presence" + Style.RESET_ALL)
    print(Fore.CYAN + "4. Start Autoreply" + Style.RESET_ALL)
    print()


def _read_line_with_cancel(prompt: str) -> Optional[str]:
    try:
        return input(prompt)
    except KeyboardInterrupt:
        return None


def prompt_token(config: dict[str, str]) -> None:
    while True:
        clear_screen()
        print(Fore.CYAN + "Enter Discord Token" + Style.RESET_ALL)
        print(Fore.YELLOW + "(Press Ctrl+C to cancel)" + Style.RESET_ALL)
        print()
        
        try:
            token_input = _read_line_with_cancel(f"{Fore.YELLOW}Token: {Style.RESET_ALL}")
        except KeyboardInterrupt:
            clear_screen()
            return

        if token_input is None:
            clear_screen()
            return

        token = token_input.strip()
        if not token:
            continue

        print(Fore.YELLOW + "Validating token..." + Style.RESET_ALL)
        is_valid = validate_token_http(token)
        
        if is_valid:
            print(Fore.GREEN + "Valid Token" + Style.RESET_ALL)
            config["token"] = token
            _save_config(config)
            time.sleep(1.2)
            clear_screen()
            return

        print(Fore.RED + "Invalid Token" + Style.RESET_ALL)
        time.sleep(1.5)


def _capture_multiline_input() -> Optional[str]:
    print(Fore.CYAN + "Input Message :" + Style.RESET_ALL)
    print(Fore.WHITE + "Press Enter for a new line." + Style.RESET_ALL)
    print(Fore.YELLOW + "Use Ctrl+S to save, Ctrl+X to cancel." + Style.RESET_ALL)

    if termios is None or tty is None:
        print(Fore.RED + "Raw input not supported on this platform. Enter a single line message." + Style.RESET_ALL)
        try:
            return input("> ")
        except KeyboardInterrupt:
            return None

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    buffer: list[str] = []

    skip_lf = False
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if skip_lf:
                skip_lf = False
                if ch == "\n":
                    continue
            if ch == "\x13":
                sys.stdout.write("\n")
                sys.stdout.flush()
                break
            if ch == "\x18":
                sys.stdout.write("\n")
                sys.stdout.flush()
                return None
            if ch == "\r":
                buffer.append("\n")
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                skip_lf = True
                continue
            if ch == "\n":
                buffer.append("\n")
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                continue
            if ch in ("\x7f", "\b"):
                if buffer:
                    buffer.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            buffer.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return "".join(buffer).strip("\n")


def prompt_message(config: dict[str, str]) -> None:
    clear_screen()
    message = _capture_multiline_input()
    if message is None:
        time.sleep(0.8)
        clear_screen()
        return

    config["message"] = message
    _save_config(config)
    print(Fore.GREEN + "Message saved." + Style.RESET_ALL)
    time.sleep(1.2)
    clear_screen()


def prompt_presence(config: dict[str, str]) -> None:
    while True:
        clear_screen()
        print(Fore.CYAN + Style.BRIGHT + "Select Presence :" + Style.RESET_ALL)
        print("1. Online")
        print("2. Idle")
        print("3. Dnd")
        print("4. Invisible")
        print()
        try:
            choice = input("Select : ").strip()
        except KeyboardInterrupt:
            clear_screen()
            return

        mapping = {"1": "online", "2": "idle", "3": "dnd", "4": "invisible"}
        if choice in mapping:
            config["presence"] = mapping[choice]
            _save_config(config)
            print(Fore.GREEN + f"Presence set to {mapping[choice]}." + Style.RESET_ALL)
            time.sleep(1.2)
            clear_screen()
            return


def _reset_tracking_state() -> None:
    _load_id_file(REPLIED_FILE, _replied_channels, "replied.txt")
    _load_id_file(ERROR_FILE, _errored_channels, "error.txt")


async def run_autoreply_async(config: dict[str, str]) -> None:
    token = config.get("token", "").strip()
    message_text = config.get("message", "").strip()
    presence_value = config.get("presence", "").strip() or "online"

    if not token:
        print(Fore.RED + "Token is not set. Please configure it first." + Style.RESET_ALL)
        time.sleep(1.5)
        return

    if not message_text:
        print(Fore.RED + "Message is not set. Please configure it first." + Style.RESET_ALL)
        time.sleep(1.5)
        return

    clear_screen()
    print(Fore.CYAN + "========= [Logger Autoreply] =========" + Style.RESET_ALL)

    _reset_tracking_state()

    client = DiscordClient(token)
    
    periodic_check_task = None

    async def periodic_dm_check():
        await asyncio.sleep(30)
        
        check_count = 0
        while client._running:
            try:
                if client.gateway.connected and client.gateway.ready:
                    check_count += 1
                    if check_count % 5 == 0:
                        log_process(f"Bot is online and monitoring DMs... (check #{check_count})")
                    await _process_dm_channels(client, message_text)
                else:
                    log_process("Waiting for gateway to be ready...")
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            except Exception as e:
                await asyncio.sleep(60)

    @client.event
    async def on_ready():
        nonlocal periodic_check_task
        
        if client.user:
            username = client.user.get("username", "Unknown")
            user_id = client.user.get("id", "Unknown")
            log_success(f"Logged in as {username} ({user_id})")
        
        await client.change_presence(presence_value)
        log_success(f"Presence set to {presence_value}")
        log_success("Bot is now online and listening for DM messages...")
        log_process("Press Ctrl+C to stop the bot")
        
        asyncio.create_task(_process_dm_channels(client, message_text))
        
        if periodic_check_task is None:
            periodic_check_task = asyncio.create_task(periodic_dm_check())
    
    @client.event
    async def on_disconnect():
        log_process("Gateway disconnected. Attempting to reconnect...")
    
    @client.event
    async def on_resumed():
        log_success("Gateway connection resumed successfully!")

    @client.event
    async def on_message(message: Message):
        if client.user and message.author.id == int(client.user.get("id", 0)):
            return

        if message.guild is not None:
            return

        channel_id = message.channel_id
        
        if message.author.bot:
            log_process(f"Skipping bot DM channel {channel_id}")
            await _record_error(channel_id)
            return

        if channel_id in _errored_channels or channel_id in _replied_channels:
            return

        author_label = str(message.author)
        log_process(f"[{author_label}] Queuing autoreply for channel {channel_id}")

        if _processing_lock.locked():
            log_process("Autoreply worker busy; request queued for next cycle.")
        
        asyncio.create_task(_process_dm_channels(client, message_text))

    try:
        await client.start()
    except KeyboardInterrupt:
        log_process("Stopping autoreply...")
        client._running = False
        
        if periodic_check_task:
            periodic_check_task.cancel()
            try:
                await periodic_check_task
            except asyncio.CancelledError:
                pass
        
        await client.close()
    except Exception:
        config["token"] = ""
        _save_config(config)


def run_autoreply(config: dict[str, str]) -> None:
    try:
        asyncio.run(run_autoreply_async(config))
    except KeyboardInterrupt:
        pass
    finally:
        clear_screen()


def main() -> None:
    config = _load_config()
    while True:
        try:
            display_menu(config)
            choice = input("Select Menu Number : ").strip()
        except KeyboardInterrupt:
            clear_screen()
            print(Fore.MAGENTA + "Goodbye!" + Style.RESET_ALL)
            return

        if choice == "1":
            prompt_token(config)
        elif choice == "2":
            prompt_message(config)
        elif choice == "3":
            prompt_presence(config)
        elif choice == "4":
            run_autoreply(config)
        else:
            continue


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear_screen()
        print(Fore.MAGENTA + "Goodbye!" + Style.RESET_ALL)
