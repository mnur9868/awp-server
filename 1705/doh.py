#!/usr/bin/env python3
import asyncio
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


# =====================================================================
# CARRIER DNS-OVER-HTTPS (RFC 8484 WIREFORMAT) - STDLIB ASYNCIO POOL
# =====================================================================
class DoHClientPool:
    """
    Klien RFC 8484 DNS-over-HTTPS (application/dns-message) dengan HTTP/1.1
    persistent keep-alive connection pool tanpa dependensi pihak ketiga.
    """

    USER_AGENT = (
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
    )

    def __init__(
        self,
        doh_urls: List[str],
        max_idle_per_url: int = 8,
        verify_ssl: bool = True,
    ):
        self.doh_urls = list(doh_urls)
        self.max_idle_per_url = max(2, max_idle_per_url)
        self._parsed: Dict[str, Tuple[str, int, str, bool]] = {}
        self._idle_conns: Dict[str, List[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]] = {}

        if verify_ssl:
            self._ssl_ctx = ssl.create_default_context()
        else:
            self._ssl_ctx = ssl._create_unverified_context()

        for u in self.doh_urls:
            self._register_url(u)

    def _register_url(self, url: str) -> Tuple[str, int, str, bool]:
        if url in self._parsed:
            return self._parsed[url]
        p = urlparse(url)
        is_https = p.scheme.lower() != "http"
        host = p.hostname or "dns.google"
        port = p.port or (443 if is_https else 80)
        path = p.path or "/dns-query"
        if p.query:
            path = f"{path}?{p.query}"
        info = (host, port, path, is_https)
        self._parsed[url] = info
        self._idle_conns.setdefault(url, [])
        return info

    async def _open_connection(
        self, url: str, timeout: float
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        host, port, _, is_https = self._register_url(url)
        ssl_arg = self._ssl_ctx if is_https else None
        sni_arg = host if is_https else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_arg, server_hostname=sni_arg),
            timeout=timeout,
        )
        sock = writer.get_extra_info("socket")
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        return reader, writer

    def _pop_idle(
        self, url: str
    ) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        pool = self._idle_conns.get(url)
        while pool:
            reader, writer = pool.pop()
            if not writer.is_closing() and not reader.at_eof():
                return reader, writer
            try:
                writer.close()
            except Exception:
                pass
        return None

    def _return_idle(
        self, url: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        if writer.is_closing() or reader.at_eof():
            try:
                writer.close()
            except Exception:
                pass
            return
        pool = self._idle_conns.setdefault(url, [])
        if len(pool) < self.max_idle_per_url:
            pool.append((reader, writer))
        else:
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    async def _read_http_response(
        reader: asyncio.StreamReader,
    ) -> Tuple[int, bytes, bool]:
        status_line = await reader.readline()
        if not status_line:
            raise EOFError("Empty HTTP status line")
        parts = status_line.decode("latin-1").strip().split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise ValueError(f"Invalid HTTP status: {status_line!r}")
        status_code = int(parts[1])

        headers: Dict[str, str] = {}
        while True:
            line = await reader.readline()
            if not line:
                raise EOFError("Unexpected EOF in HTTP headers")
            if line in (b"\r\n", b"\n"):
                break
            decoded = line.decode("latin-1")
            if ":" in decoded:
                k, v = decoded.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        conn_hdr = headers.get("connection", "").lower()
        keep_alive = conn_hdr != "close"

        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = bytearray()
            while True:
                sz_line = await reader.readline()
                if not sz_line:
                    raise EOFError("Unexpected EOF in chunked body")
                sz_hex = sz_line.strip().split(b";", 1)[0]
                chunk_len = int(sz_hex, 16)
                if chunk_len == 0:
                    # Baca trailing CRLF
                    await reader.readline()
                    break
                body.extend(await reader.readexactly(chunk_len))
                await reader.readexactly(2)  # CRLF setelah chunk
            return status_code, bytes(body), keep_alive

        cl_str = headers.get("content-length", "")
        if cl_str.isdigit():
            cl = int(cl_str)
            body = await reader.readexactly(cl) if cl > 0 else b""
            return status_code, body, keep_alive

        # Fallback read until EOF
        body = await reader.read(65535)
        return status_code, body, False

    async def _roundtrip_once(
        self,
        url: str,
        dns_wire_query: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float,
    ) -> Tuple[int, bytes]:
        host, _, path, _ = self._register_url(url)
        req_head = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {self.USER_AGENT}\r\n"
            f"Content-Type: application/dns-message\r\n"
            f"Accept: application/dns-message\r\n"
            f"Content-Length: {len(dns_wire_query)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("ascii")

        writer.write(req_head + dns_wire_query)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        status_code, body, keep_alive = await asyncio.wait_for(
            self._read_http_response(reader), timeout=timeout
        )
        if keep_alive:
            self._return_idle(url, reader, writer)
        else:
            try:
                writer.close()
            except Exception:
                pass
        return status_code, body

    async def exchange(
        self, dns_wire_query: bytes, url: str, timeout: float = 2.2
    ) -> Optional[bytes]:
        """
        Kirim raw DNS wire query ke endpoint DoH via HTTP POST RFC 8484
        dan kembalikan raw DNS wire response.
        """
        pooled = self._pop_idle(url)
        if pooled is not None:
            reader, writer = pooled
            try:
                status, body = await self._roundtrip_once(
                    url, dns_wire_query, reader, writer, timeout
                )
                return body if status == 200 and body else None
            except Exception:
                try:
                    writer.close()
                except Exception:
                    pass
                # Soket idle diputus server/CDN; coba ulang 1x dengan koneksi baru

        reader, writer = await self._open_connection(url, timeout)
        try:
            status, body = await self._roundtrip_once(
                url, dns_wire_query, reader, writer, timeout
            )
            return body if status == 200 and body else None
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            return None

    async def close_all(self):
        for pool in self._idle_conns.values():
            while pool:
                _, writer = pool.pop()
                try:
                    writer.close()
                except Exception:
                    pass
