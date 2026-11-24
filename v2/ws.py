#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import os
import struct
from typing import Dict, Optional, Tuple

from config import WS_MAGIC_GUID
from crypto import SPACodec


# =====================================================================
# KAMUFLASE & FRAMING HTTP/1.1 WEBSOCKET UPGRADE (RFC 6455)
# =====================================================================
class WebSocketCamouflage:
    """Encoder/decoder HTTP/1.1 WebSocket Upgrade & Binary Frame RFC 6455."""

    @staticmethod
    def build_ws_upgrade_request(
        spa_pkt: bytes, host_header: str, ws_path: str = "/ws"
    ) -> Tuple[bytes, str]:
        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        spa_b64 = base64.urlsafe_b64encode(spa_pkt).decode("ascii").rstrip("=")
        req = (
            f"GET {ws_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"X-AWP-SPA: {spa_b64}\r\n"
            f"User-Agent: Mozilla/5.0 (Linux; Android 14) Chrome/131.0.0.0 Mobile\r\n"
            f"\r\n"
        ).encode("ascii")
        return req, ws_key

    @classmethod
    def parse_ws_upgrade_request(
        cls, psk: str, raw_headers: bytes
    ) -> Optional[Tuple[bytes, int, str]]:
        try:
            text = raw_headers.decode("latin-1")
            lines = text.split("\r\n")
            if not lines or not lines[0].startswith("GET "):
                return None
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if headers.get("upgrade", "").lower() != "websocket":
                return None
            ws_key = headers.get("sec-websocket-key", "")
            spa_b64 = headers.get("x-awp-spa", "")
            if not ws_key or not spa_b64:
                return None

            pad = "=" * ((4 - len(spa_b64) % 4) % 4)
            spa_bytes = base64.urlsafe_b64decode(spa_b64 + pad)
            res = SPACodec.verify_spa_packet(psk, spa_bytes)
            if res is None:
                return None
            return res[0], res[1], ws_key
        except Exception:
            return None

    @classmethod
    def build_ws_upgrade_response(cls, ws_key: str, ack_wire: bytes) -> bytes:
        accept_raw = hashlib.sha1(
            (ws_key + WS_MAGIC_GUID).encode("ascii")
        ).digest()
        accept_b64 = base64.b64encode(accept_raw).decode("ascii")
        resp_hdr = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_b64}\r\n"
            "\r\n"
        ).encode("ascii")
        return resp_hdr + cls.encode_ws_frame(ack_wire, mask=False)

    @staticmethod
    def encode_ws_frame(payload: bytes, mask: bool = True) -> bytes:
        length = len(payload)
        mask_bit = 0x80 if mask else 0x00
        out = bytearray([0x82])
        if length < 126:
            out.append(mask_bit | length)
        elif length <= 65535:
            out.append(mask_bit | 126)
            out.extend(struct.pack("!H", length))
        else:
            out.append(mask_bit | 127)
            out.extend(struct.pack("!Q", length))

        if mask:
            mkey = os.urandom(4)
            out.extend(mkey)
            masked = bytes(b ^ mkey[i & 3] for i, b in enumerate(payload))
            out.extend(masked)
        else:
            out.extend(payload)
        return bytes(out)

    @staticmethod
    async def read_ws_frame(reader: asyncio.StreamReader) -> bytes:
        while True:
            hdr2 = await reader.readexactly(2)
            opcode = hdr2[0] & 0x0F
            masked = (hdr2[1] & 0x80) != 0
            length = hdr2[1] & 0x7F

            if length == 126:
                length = struct.unpack("!H", await reader.readexactly(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", await reader.readexactly(8))[0]

            if length > 262144:
                raise ValueError("WebSocket frame terlalu besar")

            mkey = await reader.readexactly(4) if masked else b""
            data = await reader.readexactly(length) if length > 0 else b""
            if masked and data:
                data = bytes(b ^ mkey[i & 3] for i, b in enumerate(data))

            if opcode == 0x08:
                raise EOFError("WebSocket closed")
            if opcode in (0x09, 0x0A):
                continue
            return data
