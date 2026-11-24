#!/usr/bin/env python3
import asyncio
from datetime import datetime
import socket
import struct
from typing import Awaitable, Callable, Dict, Tuple

from config import TYPE_STREAM_CLOSE, TYPE_STREAM_DATA, TYPE_STREAM_OPEN


def _vts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


# =====================================================================
# LOCAL INBOUND HANDLERS (SOCKS5 & TCP/SSH PORT FORWARDER)
# =====================================================================
class LocalInboundHandler:
    """Menangani koneksi lokal SOCKS5 dan TCP/SSH port forward ke terowongan AWP."""

    def __init__(
        self,
        streams: Dict[int, Tuple[asyncio.StreamReader, asyncio.StreamWriter]],
        allocate_stream_id: Callable[[], int],
        has_fast_carrier: Callable[[], bool],
        send_frame: Callable[[int, int, bytes], Awaitable[None]],
        verbose: bool = False,
    ):
        self.streams = streams
        self.allocate_stream_id = allocate_stream_id
        self.has_fast_carrier = has_fast_carrier
        self.send_frame = send_frame
        self.verbose = verbose

    def _vlog(self, msg: str):
        if self.verbose:
            print(f"[{_vts()}][VERBOSE][INBOUND] {msg}")

    async def handle_socks5_client(
        self, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter
    ):
        sock = local_writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        peer = local_writer.get_extra_info("peername")
        stream_id = None
        dest_label = ""
        try:
            greeting = await asyncio.wait_for(local_reader.readexactly(2), timeout=15.0)
            if greeting[0] != 0x05:
                return
            await local_reader.readexactly(greeting[1])
            local_writer.write(b"\x05\x00")
            await local_writer.drain()

            req = await asyncio.wait_for(local_reader.readexactly(4), timeout=15.0)
            _, cmd, _, atyp = req
            if cmd != 0x01:
                local_writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await local_writer.drain()
                return

            if atyp == 0x01:
                dest_host = socket.inet_ntoa(await local_reader.readexactly(4))
            elif atyp == 0x03:
                dlen = (await local_reader.readexactly(1))[0]
                dest_host = (await local_reader.readexactly(dlen)).decode(
                    "utf-8", errors="ignore"
                )
            elif atyp == 0x04:
                dest_host = socket.inet_ntop(
                    socket.AF_INET6, await local_reader.readexactly(16)
                )
            else:
                return

            dest_port = struct.unpack("!H", await local_reader.readexactly(2))[0]
            dest_label = f"{dest_host}:{dest_port}"
            stream_id = self.allocate_stream_id()
            self.streams[stream_id] = (local_reader, local_writer)
            self._vlog(f"SOCKS5 SID={stream_id} OPEN -> {dest_label} (from {peer})")

            await self.send_frame(
                TYPE_STREAM_OPEN, stream_id, dest_label.encode("utf-8")
            )

            local_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await local_writer.drain()

            while True:
                read_sz = 32768 if self.has_fast_carrier() else 2048
                data = await local_reader.read(read_sz)
                if not data:
                    self._vlog(f"SOCKS5 SID={stream_id} ({dest_label}) local EOF")
                    break
                self._vlog(f"SOCKS5 SID={stream_id} TX {len(data)}B -> {dest_label}")
                await self.send_frame(TYPE_STREAM_DATA, stream_id, data)
        except Exception as e:
            self._vlog(f"SOCKS5 SID={stream_id} ({dest_label}) exception: {type(e).__name__}: {e}")
        finally:
            if stream_id is not None and stream_id in self.streams:
                self.streams.pop(stream_id, None)
                self._vlog(f"SOCKS5 SID={stream_id} ({dest_label}) sending STREAM_CLOSE")
                try:
                    await self.send_frame(TYPE_STREAM_CLOSE, stream_id, b"")
                except Exception:
                    pass
            try:
                local_writer.close()
            except Exception:
                pass

    async def handle_tcp_forward_client(
        self,
        local_reader: asyncio.StreamReader,
        local_writer: asyncio.StreamWriter,
        remote_target: str,
    ):
        sock = local_writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        peer = local_writer.get_extra_info("peername")
        stream_id = None
        try:
            stream_id = self.allocate_stream_id()
            self.streams[stream_id] = (local_reader, local_writer)
            self._vlog(f"FWD SID={stream_id} OPEN -> {remote_target} (from {peer})")

            await self.send_frame(
                TYPE_STREAM_OPEN, stream_id, remote_target.encode("utf-8")
            )
            while True:
                read_sz = 32768 if self.has_fast_carrier() else 2048
                data = await local_reader.read(read_sz)
                if not data:
                    self._vlog(f"FWD SID={stream_id} ({remote_target}) local EOF")
                    break
                self._vlog(f"FWD SID={stream_id} TX {len(data)}B -> {remote_target}")
                await self.send_frame(TYPE_STREAM_DATA, stream_id, data)
        except Exception as e:
            self._vlog(f"FWD SID={stream_id} ({remote_target}) exception: {type(e).__name__}: {e}")
        finally:
            if stream_id is not None and stream_id in self.streams:
                self.streams.pop(stream_id, None)
                self._vlog(f"FWD SID={stream_id} ({remote_target}) sending STREAM_CLOSE")
                try:
                    await self.send_frame(TYPE_STREAM_CLOSE, stream_id, b"")
                except Exception:
                    pass
            try:
                local_writer.close()
            except Exception:
                pass
