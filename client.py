#!/usr/bin/env python3
import asyncio
from datetime import datetime
import os
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

from camouflage import CamouflageCodec
from config import (
    AWPConfig,
    CARRIER_ID_DNS,
    CARRIER_ID_TCP,
    CARRIER_ID_UDP,
    DNS_LEGACY_DOWNLINK_CHUNK,
    DNS_MAX_DOWNLINK_CHUNK,
    EDNS0_LEGACY_PAYLOAD_SIZE,
    FLAG_UDP_CARRIER,
    PROTOCOL_BANNER,
    TYPE_CARRIER_JUMP,
    TYPE_FEC_PARITY,
    TYPE_HEARTBEAT,
    TYPE_SPA_HANDSHAKE,
    TYPE_STREAM_CLOSE,
    TYPE_STREAM_DATA,
    TYPE_STREAM_OPEN,
)
from crypto import AWPv3Crypto
from inbound import LocalInboundHandler
from quic_udp import FecEngine
from slowdns import AdaptiveGlobalQpsPacer, DnsArqEngine, DnsCodec


def _vts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


# =====================================================================
# CLIENT ENGINE, PIPELINED CARRIERS & LOCAL INBOUNDS
# =====================================================================
class _ClientUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: "AWPClientNode"):
        self.node = node

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.node.udp_transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        try:
            unwrapped = CamouflageCodec.unwrap_quic_mimic(data)
            frame = self.node.udp_crypto.decode_frame(unwrapped)
            self.node.on_udp_packet_received(frame, addr)
        except Exception:
            pass

    def connection_lost(self, exc: Optional[Exception]):
        self.node.udp_ready = False
        self.node._refresh_ready_state()


class _ClientDNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: "AWPClientNode"):
        self.node = node

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.node.dns_transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.node.on_dns_datagram_received(data)


class AWPClientNode:
    def __init__(self, cfg: AWPConfig):
        self.cfg = cfg
        self.jump_targets: List[Tuple[str, int]] = []
        for p in [cfg.port, cfg.dns_port] + cfg.jump_ports:
            if (cfg.host, p) not in self.jump_targets:
                self.jump_targets.append((cfg.host, p))

        self.zone_labels = [lbl.lower() for lbl in cfg.dns_zone.strip(".").split(".") if lbl]
        self.max_uplink_arq_bytes = CamouflageCodec.max_dns_uplink_arq_bytes(self.zone_labels)
        safe_uplink_data = min(
            cfg.dns_uplink_chunk,
            max(28, self.max_uplink_arq_bytes - DnsArqEngine.ARQ_HDR_SIZE - DnsArqEngine.SUB_HDR_SIZE),
        )

        self.session_token = os.urandom(8)

        self.tcp_crypto = AWPv3Crypto(
            cfg.psk, self.session_token, CARRIER_ID_TCP, is_server=False, ordered=True
        )
        self.udp_crypto = AWPv3Crypto(
            cfg.psk, self.session_token, CARRIER_ID_UDP, is_server=False, ordered=False
        )
        self.dns_crypto = AWPv3Crypto(
            cfg.psk, self.session_token, CARRIER_ID_DNS, is_server=False, ordered=False
        )

        self.dns_arq = DnsArqEngine(
            self.dns_crypto,
            is_server=False,
            initial_edns=cfg.edns_size,
            max_inflight=cfg.dns_inflight,
            uplink_chunk=safe_uplink_data,
            base_rto=cfg.dns_rto,
            verbose=cfg.verbose,
        )
        self.udp_fec = FecEngine(cfg.fec_group_size)
        self.qps_pacer = AdaptiveGlobalQpsPacer(
            base_qps=cfg.dns_qps, max_qps=cfg.dns_max_qps
        )

        # State TCP (TLS1.3 & WS-HTTP)
        self.tcp_writer: Optional[asyncio.StreamWriter] = None
        self.active_tcp_framing: str = "tls"
        self.tcp_ready = False
        self.active_tcp_target: Optional[Tuple[str, int]] = None
        self.tcp_rtt_ms = 999.0
        self.tcp_lock = asyncio.Lock()

        # State QUIC-UDP
        self.udp_transport: Optional[asyncio.DatagramTransport] = None
        self.udp_ready = False
        self.active_udp_target: Optional[Tuple[str, int]] = None
        self.udp_last_pong = 0.0
        self.udp_rtt_ms = 999.0
        self.jump_event = asyncio.Event()

        # State DNS-ARQ & Pipelining
        self.dns_transport: Optional[asyncio.DatagramTransport] = None
        self.dns_ready = False
        self.dns_last_pong = 0.0
        self.dns_rtt_ms = 120.0
        self.dns_wake_event = asyncio.Event()
        self.dns_downlink_burst_until: float = 0.0
        self.dns_no_opt_streak = 0
        self.dns_silent_drop_streak = 0
        self.dns_last_small_ok = 0.0
        self.dns_pending_txid: Dict[int, asyncio.Future] = {}
        self.dns_next_txid = int.from_bytes(os.urandom(2), "big")
        self.resolver_rtt: Dict[str, float] = {r: 140.0 for r in cfg.dns_resolvers}
        self.resolver_fail: Dict[str, int] = {r: 0 for r in cfg.dns_resolvers}
        self.resolver_inflight: Dict[str, int] = {r: 0 for r in cfg.dns_resolvers}
        self.resolver_cooldown_until: Dict[str, float] = {r: 0.0 for r in cfg.dns_resolvers}

        # State Stream & Statistik
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.any_carrier_ready = asyncio.Event()
        self.streams: Dict[int, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.next_stream_id = 1

        self.inbound = LocalInboundHandler(
            streams=self.streams,
            allocate_stream_id=self.allocate_stream_id,
            has_fast_carrier=self.has_fast_carrier,
            send_frame=self.send_frame,
            verbose=cfg.verbose,
        )

    def _vlog(self, msg: str):
        if self.cfg.verbose:
            print(f"[{_vts()}][VERBOSE][CLI] {msg}")

    def allocate_stream_id(self) -> int:
        sid = self.next_stream_id
        self.next_stream_id = (self.next_stream_id % 65000) + 1
        return sid

    def has_fast_carrier(self) -> bool:
        return self.udp_ready or self.tcp_ready

    def active_carrier_label(self) -> str:
        if self.tcp_ready and self.active_tcp_target:
            tag = "WS-HTTP" if self.active_tcp_framing == "ws" else "TLS1.3-TCP"
            return f"{tag}({self.active_tcp_target[1]})"
        if self.udp_ready and self.active_udp_target:
            return f"QUIC-UDP({self.active_udp_target[1]})"
        if self.dns_ready:
            chunk = self.dns_arq.downlink_chunk_limit()
            return (
                f"DNS-ARQ(EDNS={self.dns_arq.edns_size}B,Chunk={chunk}B,"
                f"QPS={self.qps_pacer.current_qps:.0f},RTO={self.dns_arq.current_rto():.2f}s,"
                f"RTT={self.dns_rtt_ms:.0f}ms)"
            )
        return "CONNECTING"

    def _refresh_ready_state(self):
        if self.udp_ready or self.tcp_ready or self.dns_ready:
            self.any_carrier_ready.set()
        else:
            self.any_carrier_ready.clear()

    def _apply_dns_jump_endpoints(self, raw_spec: str):
        if self.cfg.carrier_mode == "dns":
            return
        updated = False
        for item in raw_spec.split(","):
            item = item.strip()
            if not item or ":" not in item:
                continue
            h, p_s = item.rsplit(":", 1)
            if not p_s.isdigit():
                continue
            target = (h.strip() if h.strip() else self.cfg.host, int(p_s))
            if target not in self.jump_targets:
                self.jump_targets.append(target)
                updated = True
        if updated:
            print(f"[{PROTOCOL_BANNER}] DNS-JUMPER TARGET BARU -> {self.jump_targets}")
            self.jump_event.set()

    def _trigger_dns_edns_fallback(self, reason: str):
        if self.dns_arq.edns_size <= EDNS0_LEGACY_PAYLOAD_SIZE:
            return
        prev_size = self.dns_arq.edns_size
        self.dns_arq.edns_size = EDNS0_LEGACY_PAYLOAD_SIZE
        self.dns_no_opt_streak = 0
        self.dns_silent_drop_streak = 0
        self.dns_wake_event.set()
        print(
            f"[{PROTOCOL_BANNER}] DNS-ARQ FALLBACK ({reason}) -> "
            f"EDNS0={prev_size}B->{self.dns_arq.edns_size}B "
            f"| Chunk={DNS_MAX_DOWNLINK_CHUNK}B->{DNS_LEGACY_DOWNLINK_CHUNK}B"
        )

    def _pick_best_resolver(self, worker_idx: int) -> str:
        now = time.monotonic()
        active = [
            r
            for r in self.cfg.dns_resolvers
            if self.resolver_fail.get(r, 0) < 3
            and now >= self.resolver_cooldown_until.get(r, 0.0)
        ]
        if not active:
            # Beri 1 probe periodik ke resolver yang sudah melewati masa cooldown
            expired_cd = [
                r
                for r in self.cfg.dns_resolvers
                if now >= self.resolver_cooldown_until.get(r, 0.0)
            ]
            pool = expired_cd if expired_cd else self.cfg.dns_resolvers
        else:
            pool = active

        ranked = sorted(
            pool,
            key=lambda r: (
                self.resolver_inflight.get(r, 0) * 110.0
                + self.resolver_rtt.get(r, 150.0)
                + (self.resolver_fail.get(r, 0) * 80.0)
            ),
        )
        top_n = min(len(ranked), max(1, min(3, len(ranked))))
        return ranked[worker_idx % top_n]

    def _trigger_downlink_burst(self, duration_sec: float = 1.5):
        self.dns_downlink_burst_until = max(
            self.dns_downlink_burst_until, time.monotonic() + duration_sec
        )
        self.dns_wake_event.set()

    # --- Carrier DNS ---
    def _alloc_dns_txid(self) -> int:
        for _ in range(65535):
            self.dns_next_txid = (self.dns_next_txid + 1) & 0xFFFF
            if self.dns_next_txid != 0 and self.dns_next_txid not in self.dns_pending_txid:
                return self.dns_next_txid
        return 1

    def on_dns_datagram_received(self, data: bytes):
        if len(data) < 2:
            return
        tx_id = struct.unpack("!H", data[:2])[0]
        fut = self.dns_pending_txid.pop(tx_id, None)
        if fut and not fut.done():
            fut.set_result(data)

    async def _dns_exchange(
        self, wire_payload: bytes, resolver_ip: str, timeout: float = 0.65
    ) -> Optional[Tuple[bool, int, bytes]]:
        if not self.dns_transport or self.dns_transport.is_closing():
            return None
        loop = asyncio.get_running_loop()
        tx_id = self._alloc_dns_txid()
        pkt = CamouflageCodec.build_dns_txt_query(
            tx_id, wire_payload, self.zone_labels, edns_udp_size=self.dns_arq.edns_size
        )
        fut: asyncio.Future = loop.create_future()
        self.dns_pending_txid[tx_id] = fut
        self.resolver_inflight[resolver_ip] = self.resolver_inflight.get(resolver_ip, 0) + 1
        t0 = time.monotonic()
        try:
            self.dns_transport.sendto(pkt, (resolver_ip, self.cfg.dns_port))
            raw_resp = await asyncio.wait_for(fut, timeout=timeout)

            if len(raw_resp) >= 4 and (struct.unpack("!H", raw_resp[2:4])[0] & 0x0200) != 0:
                self._vlog(f"DNS tx={tx_id} res={resolver_ip} TC=1 truncated flag!")
                self._trigger_dns_edns_fallback("Resolver TC=1 Truncated")

            parsed = CamouflageCodec.parse_dns_txt_response(raw_resp, tx_id)
            if parsed is None:
                desc = DnsCodec.describe_dns_response(raw_resp)
                self._vlog(
                    f"DNS tx={tx_id} res={resolver_ip} invalid TXT response "
                    f"(len={len(raw_resp)}B, {desc})"
                )
                self.qps_pacer.on_loss()
                return None

            if self.dns_arq.edns_size > EDNS0_LEGACY_PAYLOAD_SIZE:
                if not CamouflageCodec.response_has_edns_opt(raw_resp):
                    self.dns_no_opt_streak += 1
                    self._vlog(
                        f"DNS tx={tx_id} res={resolver_ip} missing OPT RR (streak={self.dns_no_opt_streak})"
                    )
                    if self.dns_no_opt_streak >= 2:
                        self._trigger_dns_edns_fallback("Proxy Stripped EDNS0 OPT")
                else:
                    self.dns_no_opt_streak = 0

            self.dns_silent_drop_streak = 0
            self.dns_last_small_ok = time.monotonic()

            rtt = max(1.0, (time.monotonic() - t0) * 1000.0)
            prev_r = self.resolver_rtt.get(resolver_ip, rtt)
            self.resolver_rtt[resolver_ip] = (prev_r * 0.70) + (rtt * 0.30)
            self.resolver_fail[resolver_ip] = 0
            self.resolver_cooldown_until[resolver_ip] = 0.0
            self.dns_rtt_ms = min(self.resolver_rtt.values())
            self.dns_arq.update_rtt_ms(self.dns_rtt_ms)
            self.dns_last_pong = time.monotonic()
            self.qps_pacer.on_success(rtt)

            has_more, backlog_hint, down_wire = parsed
            if self.cfg.verbose and (len(down_wire) > 0 or has_more or backlog_hint > 0):
                self._vlog(
                    f"DNS OK tx={tx_id} res={resolver_ip} rtt={rtt:.0f}ms "
                    f"q_pkt={len(pkt)}B resp_pkt={len(raw_resp)}B down_wire={len(down_wire)}B "
                    f"more={int(has_more)} backlog={backlog_hint}"
                )
            return parsed
        except asyncio.CancelledError:
            self.dns_pending_txid.pop(tx_id, None)
            raise
        except Exception as e:
            self.dns_pending_txid.pop(tx_id, None)
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            self._vlog(
                f"DNS DROP/TIMEOUT tx={tx_id} res={resolver_ip} after={elapsed_ms:.0f}ms "
                f"err={type(e).__name__} q_pkt={len(pkt)}B inflight={self.resolver_inflight.get(resolver_ip, 0)}"
            )
            if (
                self.dns_ready
                and self.dns_arq.edns_size > EDNS0_LEGACY_PAYLOAD_SIZE
                and (bool(self.streams) or self.dns_arq.has_pending_work())
                and (time.monotonic() - self.dns_last_small_ok) < 25.0
            ):
                self.dns_silent_drop_streak += 1
                if self.dns_silent_drop_streak >= 2:
                    self._trigger_dns_edns_fallback("2x Timeout on >512B Downlink")
                    self.resolver_fail[resolver_ip] = 0
                    return None

            fails = self.resolver_fail.get(resolver_ip, 0) + 1
            self.resolver_fail[resolver_ip] = fails
            if fails >= 3:
                cd_sec = min(30.0, 6.0 * (fails - 2))
                self.resolver_cooldown_until[resolver_ip] = time.monotonic() + cd_sec
            prev_r = self.resolver_rtt.get(resolver_ip, 250.0)
            self.resolver_rtt[resolver_ip] = min(900.0, prev_r * 1.15 + 35.0)
            self.qps_pacer.on_loss()
            return None
        finally:
            self.resolver_inflight[resolver_ip] = max(
                0, self.resolver_inflight.get(resolver_ip, 1) - 1
            )

    async def maintain_dns_carrier(self):
        loop = asyncio.get_running_loop()
        first_up = True
        while True:
            try:
                if self.dns_transport is None or self.dns_transport.is_closing():
                    await loop.create_datagram_endpoint(
                        lambda: _ClientDNSProtocol(self), local_addr=("0.0.0.0", 0)
                    )

                for r_ip in self.cfg.dns_resolvers:
                    self.resolver_fail[r_ip] = 0
                    self.resolver_inflight[r_ip] = 0
                    self.resolver_cooldown_until[r_ip] = 0.0

                spa_pkt = CamouflageCodec.build_spa_packet(
                    self.cfg.psk, self.session_token, CARRIER_ID_DNS, min_pad=0, max_pad=0
                )
                handshaked = False
                for r_ip in self.cfg.dns_resolvers:
                    self._vlog(f"Sending DNS SPA handshake via {r_ip}:{self.cfg.dns_port}")
                    res = await self._dns_exchange(spa_pkt, r_ip, timeout=1.2)
                    if res is not None and res[2]:
                        ack_frame = self.dns_crypto.decode_frame(res[2])
                        if ack_frame["type"] == TYPE_SPA_HANDSHAKE:
                            handshaked = True
                            break

                if handshaked:
                    for entry in self.dns_arq.unacked.values():
                        entry[0] = 0.0
                    self.dns_silent_drop_streak = 0
                    self.dns_last_small_ok = time.monotonic()
                    self.dns_ready = True
                    self._refresh_ready_state()

                    if first_up:
                        first_up = False
                        print(
                            f"[{PROTOCOL_BANNER}] DNS-JUMPER AKTIF -> "
                            f"Resolvers={','.join(self.cfg.dns_resolvers)}:{self.cfg.dns_port} "
                            f"| Workers={self.cfg.dns_workers} | QPS={self.cfg.dns_qps:.0f}..{self.cfg.dns_max_qps:.0f} "
                            f"| Win={self.cfg.dns_inflight} | EDNS0={self.dns_arq.edns_size}B "
                            f"| Token={self.session_token.hex()} | RTT={self.dns_rtt_ms:.0f}ms"
                        )

                    workers = [
                        asyncio.create_task(self._dns_poll_worker(i))
                        for i in range(self.cfg.dns_workers)
                    ]
                    try:
                        while self.dns_ready:
                            await asyncio.sleep(2.5)
                            if time.monotonic() - self.dns_last_pong > 45.0:
                                self._vlog("DNS carrier heartbeat expired (>45s without pong)")
                                self.dns_ready = False
                                self._refresh_ready_state()
                                break
                    finally:
                        for w in workers:
                            w.cancel()

                self.dns_ready = False
                self._refresh_ready_state()
                await asyncio.sleep(1.2)
            except Exception as e:
                self.dns_ready = False
                self._refresh_ready_state()
                print(f"[{PROTOCOL_BANNER}] DNS-JUMPER error ({e}), retry 1.2s...")
                await asyncio.sleep(1.2)

    async def _dns_poll_worker(self, worker_idx: int):
        # Stagger awal antar-worker untuk mencegah microburst pada NAT/resolver operator
        await asyncio.sleep(worker_idx * 0.012)
        idle_delay = 0.03 + (worker_idx * 0.012)
        while self.dns_ready:
            if (
                self.has_fast_carrier()
                and not self.dns_arq.has_pending_work()
                and not self.dns_arq.rx_ooo
            ):
                timeout = 1.5 if worker_idx > 0 else 8.0
                try:
                    await asyncio.wait_for(self.dns_wake_event.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    pass
                if worker_idx > 0:
                    continue

            if (
                not self.streams
                and not self.dns_arq.has_pending_work()
                and not self.dns_arq.rx_ooo
                and time.monotonic() >= self.dns_downlink_burst_until
                and worker_idx >= 3
            ):
                try:
                    await asyncio.wait_for(self.dns_wake_event.wait(), timeout=0.45)
                except asyncio.TimeoutError:
                    pass
                continue

            resolver_ip = self._pick_best_resolver(worker_idx)
            await self.qps_pacer.acquire(resolver_ip=resolver_ip)

            wire_out, is_data = self.dns_arq.pop_next_wire(
                emit_idle_poll=True, max_arq_bytes_override=self.max_uplink_arq_bytes
            )
            if (
                not self.dns_arq.has_pending_work()
                and not self.dns_arq.rx_ooo
                and time.monotonic() >= self.dns_downlink_burst_until
            ):
                self.dns_wake_event.clear()

            # Fast UDP timeout berbasis RTT aktual (~380ms-650ms) agar worker tidak macet
            base_est = max(0.06, self.resolver_rtt.get(resolver_ip, 140.0) / 1000.0)
            dyn_timeout = max(0.38, min(0.75, base_est * 3.0 + 0.18))

            res = await self._dns_exchange(wire_out, resolver_ip, timeout=dyn_timeout)
            if res is None:
                await asyncio.sleep(0.02)
                continue

            has_more, backlog_hint, down_wire = res
            if down_wire:
                try:
                    frame = self.dns_crypto.decode_frame(down_wire)
                    await self._dispatch_downlink_frame(frame, source_carrier="dns")
                except Exception as e:
                    self._vlog(f"DNS downlink frame decode err: {type(e).__name__}: {e}")

            if has_more or backlog_hint > 0 or self.dns_arq.rx_ooo:
                self._trigger_downlink_burst(duration_sec=1.2)

            in_burst = time.monotonic() < self.dns_downlink_burst_until
            if (
                has_more
                or backlog_hint > 0
                or in_burst
                or is_data
                or self.dns_arq.has_pending_work()
                or self.dns_arq.needs_immediate_ack()
                or self.dns_arq.has_stalled_gap()
            ):
                idle_delay = 0.005
            else:
                max_sleep = 0.10 if self.streams else 0.30
                idle_delay = min(max_sleep, idle_delay + 0.03)
                try:
                    await asyncio.wait_for(self.dns_wake_event.wait(), timeout=idle_delay)
                except asyncio.TimeoutError:
                    pass

    # --- Carrier QUIC-UDP ---
    async def maintain_udp_carrier(self):
        loop = asyncio.get_running_loop()
        first_up = True
        backoff = 3.0
        while True:
            try:
                if self.udp_transport is None or self.udp_transport.is_closing():
                    await loop.create_datagram_endpoint(
                        lambda: _ClientUDPProtocol(self), local_addr=("0.0.0.0", 0)
                    )

                self.jump_event.clear()
                for _ in range(3):
                    spa_pkt = CamouflageCodec.build_spa_packet(
                        self.cfg.psk, self.session_token, CARRIER_ID_UDP
                    )
                    quic_spa = CamouflageCodec.wrap_quic_mimic(spa_pkt, is_initial=True)
                    if self.udp_transport:
                        for target in list(self.jump_targets):
                            try:
                                self.udp_transport.sendto(quic_spa, target)
                            except Exception:
                                pass
                    await asyncio.sleep(0.12)

                for _ in range(25):
                    if self.udp_ready and (time.monotonic() - self.udp_last_pong < 4.0):
                        break
                    await asyncio.sleep(0.1)

                if (
                    self.udp_ready
                    and self.active_udp_target is not None
                    and (time.monotonic() - self.udp_last_pong < 4.0)
                ):
                    backoff = 3.0
                    if first_up:
                        first_up = False
                        print(
                            f"[{PROTOCOL_BANNER}] QUIC-UDP OFFLOAD AKTIF -> "
                            f"{self.active_udp_target[0]}:{self.active_udp_target[1]} "
                            f"| Token={self.session_token.hex()} | RTT={self.udp_rtt_ms:.1f}ms"
                        )
                    while self.udp_ready:
                        await asyncio.sleep(10.0)
                        if time.monotonic() - self.udp_last_pong > 24.0:
                            self.udp_ready = False
                            self._refresh_ready_state()
                            break
                        if (
                            self.udp_transport
                            and not self.udp_transport.is_closing()
                            and self.active_udp_target
                        ):
                            hb_wire, _, _ = self.udp_crypto.encode_frame(
                                TYPE_HEARTBEAT,
                                0,
                                struct.pack("!d", time.monotonic()),
                                flags=FLAG_UDP_CARRIER,
                            )
                            self.udp_transport.sendto(
                                CamouflageCodec.wrap_quic_mimic(hb_wire, is_initial=False),
                                self.active_udp_target,
                            )
                else:
                    self.udp_ready = False
                    self._refresh_ready_state()
                    try:
                        await asyncio.wait_for(self.jump_event.wait(), timeout=backoff)
                        backoff = 3.0
                    except asyncio.TimeoutError:
                        backoff = min(20.0, backoff * 1.5)
            except Exception:
                self.udp_ready = False
                self._refresh_ready_state()
                await asyncio.sleep(backoff)
                backoff = min(20.0, backoff * 1.5)

    def on_udp_packet_received(self, frame: dict, addr: Tuple[str, int]):
        now = time.monotonic()
        self.udp_last_pong = now
        self.active_udp_target = addr
        ftype = frame["type"]

        if ftype == TYPE_SPA_HANDSHAKE:
            was_ready = self.udp_ready
            self.udp_ready = True
            self._refresh_ready_state()
            if not was_ready and self.udp_transport and not self.udp_transport.is_closing():
                hb_wire, _, _ = self.udp_crypto.encode_frame(
                    TYPE_HEARTBEAT, 0, struct.pack("!d", now), flags=FLAG_UDP_CARRIER
                )
                self.udp_transport.sendto(
                    CamouflageCodec.wrap_quic_mimic(hb_wire, is_initial=False), addr
                )
            return

        if ftype == TYPE_HEARTBEAT and len(frame["payload"]) == 8:
            sent_ts = struct.unpack("!d", frame["payload"])[0]
            self.udp_rtt_ms = max(1.0, (now - sent_ts) * 1000.0)
            self.udp_ready = True
            self._refresh_ready_state()
            return

        asyncio.create_task(self._dispatch_downlink_frame(frame, source_carrier="udp"))

    # --- Carrier Dual-Mode TCP (TLS 1.3 & HTTP WebSocket Upgrade) ---
    async def _probe_single_tcp(
        self, host: str, port: int
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, Tuple[str, int]]:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
        return r, w, (host, port)

    async def _perform_tcp_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: Tuple[str, int],
        framing_mode: str,
    ) -> bool:
        self.tcp_crypto = AWPv3Crypto(
            self.cfg.psk,
            self.session_token,
            CARRIER_ID_TCP,
            is_server=False,
            ordered=True,
        )
        spa_pkt = CamouflageCodec.build_spa_packet(
            self.cfg.psk, self.session_token, CARRIER_ID_TCP
        )

        if framing_mode == "ws":
            host_hdr = self.cfg.tls_sni if self.cfg.tls_sni else target[0]
            req_bytes, _ = CamouflageCodec.build_ws_upgrade_request(
                spa_pkt, host_hdr, self.cfg.ws_path
            )
            writer.write(req_bytes)
            await writer.drain()

            resp_hdr = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
            if b"101 " not in resp_hdr.split(b"\r\n", 1)[0]:
                return False
            ack_wire = await asyncio.wait_for(
                CamouflageCodec.read_ws_frame(reader), timeout=5.0
            )
            ack_frame = self.tcp_crypto.decode_frame(ack_wire)
            return ack_frame["type"] == TYPE_SPA_HANDSHAKE

        writer.write(
            CamouflageCodec.wrap_tls_client_hello(spa_pkt, sni_host=self.cfg.tls_sni)
        )
        await writer.drain()

        for _ in range(4):
            rec_hdr = await asyncio.wait_for(reader.readexactly(5), timeout=5.0)
            rec_type, _, _, body_len = struct.unpack("!BBBH", rec_hdr)
            if body_len > 65535:
                return False
            rec_body = await asyncio.wait_for(reader.readexactly(body_len), timeout=5.0)
            if rec_type == 0x17:
                ack_frame = self.tcp_crypto.decode_frame(rec_body)
                return ack_frame["type"] == TYPE_SPA_HANDSHAKE
        return False

    async def maintain_tcp_carrier(self):
        first_up = True
        backoff = 3.0
        mimic_cycle = 0

        while True:
            writer: Optional[asyncio.StreamWriter] = None
            if self.cfg.tcp_mimic == "auto":
                framing_mode = "tls" if (mimic_cycle % 2 == 0) else "ws"
                mimic_cycle += 1
            else:
                framing_mode = self.cfg.tcp_mimic

            try:
                self.jump_event.clear()
                targets = [(h, p) for (h, p) in self.jump_targets if p != self.cfg.dns_port]
                tasks = [
                    asyncio.create_task(self._probe_single_tcp(h, p)) for (h, p) in targets
                ]
                winner = None
                try:
                    for fut in asyncio.as_completed(tasks):
                        try:
                            winner = await fut
                            break
                        except Exception:
                            continue
                finally:
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                        else:
                            try:
                                res = t.result()
                                if winner is None or res[1] is not winner[1]:
                                    res[1].close()
                            except Exception:
                                pass

                if winner is None:
                    raise ConnectionError("Semua target TCP gagal")

                reader, writer, chosen_target = winner
                sock = writer.get_extra_info("socket")
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                ok = await self._perform_tcp_handshake(
                    reader, writer, chosen_target, framing_mode
                )
                if not ok:
                    raise ConnectionError(f"Handshake {framing_mode.upper()} ditolak")

                backoff = 3.0
                self.tcp_writer = writer
                self.active_tcp_framing = framing_mode
                self.active_tcp_target = chosen_target
                self.tcp_ready = True
                self._refresh_ready_state()

                label = "WS-HTTP" if framing_mode == "ws" else "TLS1.3-TCP"
                tag = "OFFLOAD AKTIF" if first_up else "MIGRATED"
                first_up = False
                print(
                    f"[{PROTOCOL_BANNER}] {label} {tag} -> "
                    f"{chosen_target[0]}:{chosen_target[1]} | Token={self.session_token.hex()}"
                )

                async with self.tcp_lock:
                    hb_wire, _, _ = self.tcp_crypto.encode_frame(
                        TYPE_HEARTBEAT, 0, struct.pack("!d", time.monotonic())
                    )
                    writer.write(
                        CamouflageCodec.wrap_tcp_stream_frame(
                            framing_mode, hb_wire, is_client=True
                        )
                    )
                    await writer.drain()

                hb_task = asyncio.create_task(self._tcp_heartbeat_loop(writer, framing_mode))
                try:
                    while True:
                        rec_body = await CamouflageCodec.read_tcp_stream_frame(
                            framing_mode, reader
                        )
                        frame = self.tcp_crypto.decode_frame(rec_body)
                        await self._dispatch_downlink_frame(frame, source_carrier="tcp")
                finally:
                    hb_task.cancel()
            except Exception:
                pass
            finally:
                if self.tcp_writer is writer:
                    self.tcp_writer = None
                    self.tcp_ready = False
                    self._refresh_ready_state()
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        pass

                if self.cfg.tcp_mimic == "auto" and (mimic_cycle % 2 == 1):
                    await asyncio.sleep(0.25)
                else:
                    try:
                        await asyncio.wait_for(self.jump_event.wait(), timeout=backoff)
                        backoff = 3.0
                    except asyncio.TimeoutError:
                        backoff = min(20.0, backoff * 1.5)

    async def _tcp_heartbeat_loop(
        self, writer: asyncio.StreamWriter, framing_mode: str
    ):
        while True:
            await asyncio.sleep(15.0)
            if self.tcp_writer is writer and self.tcp_ready:
                async with self.tcp_lock:
                    hb_wire, _, _ = self.tcp_crypto.encode_frame(
                        TYPE_HEARTBEAT, 0, struct.pack("!d", time.monotonic())
                    )
                    writer.write(
                        CamouflageCodec.wrap_tcp_stream_frame(
                            framing_mode, hb_wire, is_client=True
                        )
                    )
                    await writer.drain()

    # --- Dispatch Downlink & Uplink Scheduler ---
    async def _deliver_ordered_downlink(
        self, ftype: int, sid: int, payload: bytes, source_carrier: str
    ):
        if ftype == TYPE_CARRIER_JUMP:
            self._apply_dns_jump_endpoints(payload.decode("utf-8", errors="ignore"))
            return
        if ftype == TYPE_STREAM_DATA:
            if sid in self.streams:
                _, local_writer = self.streams[sid]
                try:
                    self.rx_bytes += len(payload)
                    self._vlog(
                        f"DOWNLINK ({source_carrier.upper()}) SID={sid} -> local {len(payload)}B"
                    )
                    local_writer.write(payload)
                    await local_writer.drain()
                except Exception as e:
                    self._vlog(f"DOWNLINK SID={sid} local write err: {e}")
                    self.streams.pop(sid, None)
            else:
                self._vlog(
                    f"DOWNLINK ({source_carrier.upper()}) SID={sid} dropped ({len(payload)}B, local closed)"
                )
        elif ftype == TYPE_STREAM_CLOSE:
            reason = payload.decode("utf-8", errors="ignore") if payload else "EOF"
            self._vlog(
                f"DOWNLINK ({source_carrier.upper()}) STREAM_CLOSE SID={sid} reason={reason}"
            )
            self.dns_arq.purge_stream(sid)
            if sid in self.streams:
                _, local_writer = self.streams.pop(sid)
                try:
                    local_writer.close()
                except Exception:
                    pass
        elif ftype == TYPE_HEARTBEAT and len(payload) == 8 and source_carrier == "tcp":
            sent_ts = struct.unpack("!d", payload)[0]
            self.tcp_rtt_ms = max(1.0, (time.monotonic() - sent_ts) * 1000.0)

    async def _dispatch_downlink_frame(self, frame: dict, source_carrier: str):
        ftype = frame["type"]
        sid = frame["stream_id"]
        payload = frame["payload"]

        if source_carrier == "dns":
            await self.dns_arq.ingest_incoming(
                payload,
                lambda t, s, d: self._deliver_ordered_downlink(t, s, d, "dns"),
            )
            return

        if source_carrier == "udp":
            is_dup, recovered = self.udp_fec.process_rx_frame(frame)
            if not is_dup:
                await self._deliver_ordered_downlink(ftype, sid, payload, "udp")
            if recovered:
                await self._deliver_ordered_downlink(
                    recovered["type"], recovered["stream_id"], recovered["payload"], "udp"
                )
            return

        await self._deliver_ordered_downlink(ftype, sid, payload, source_carrier)

    async def send_frame(self, frame_type: int, stream_id: int, payload: bytes = b""):
        await asyncio.wait_for(self.any_carrier_ready.wait(), timeout=20.0)
        self.tx_bytes += len(payload)

        if self.tcp_ready and self.tcp_writer and not self.tcp_writer.is_closing():
            async with self.tcp_lock:
                wire_pkt, _, _ = self.tcp_crypto.encode_frame(
                    frame_type, stream_id, payload
                )
                framed = CamouflageCodec.wrap_tcp_stream_frame(
                    self.active_tcp_framing, wire_pkt, is_client=True
                )
                self.tcp_writer.write(framed)
                await self.tcp_writer.drain()
            return

        if (
            self.udp_ready
            and self.udp_transport is not None
            and not self.udp_transport.is_closing()
            and self.active_udp_target is not None
        ):
            try:
                wire_pkt, seq_num, clean_frame = self.udp_crypto.encode_frame(
                    frame_type, stream_id, payload, flags=FLAG_UDP_CARRIER
                )
                self.udp_transport.sendto(
                    CamouflageCodec.wrap_quic_mimic(wire_pkt, is_initial=False),
                    self.active_udp_target,
                )
                if frame_type == TYPE_STREAM_DATA:
                    parity_blob = self.udp_fec.build_tx_parity_if_ready(seq_num, clean_frame)
                    if parity_blob:
                        fec_wire, _, _ = self.udp_crypto.encode_frame(
                            TYPE_FEC_PARITY, 0, parity_blob, flags=FLAG_UDP_CARRIER
                        )
                        self.udp_transport.sendto(
                            CamouflageCodec.wrap_quic_mimic(fec_wire, is_initial=False),
                            self.active_udp_target,
                        )
                return
            except Exception:
                self.udp_ready = False
                self._refresh_ready_state()

        if self.dns_ready:
            while self.dns_arq.queued_count() > 360:
                if self.has_fast_carrier():
                    break
                await asyncio.sleep(0.008)
            self.dns_arq.enqueue(
                frame_type, stream_id, payload, wake_event=self.dns_wake_event
            )
            if frame_type in (TYPE_STREAM_OPEN, TYPE_STREAM_DATA):
                self._trigger_downlink_burst(duration_sec=2.0)
            return

        raise ConnectionError(f"Tidak ada carrier {PROTOCOL_BANNER} yang aktif")

    async def _monitor_stats(self):
        last_tx = 0
        last_rx = 0
        interval = max(2.0, self.cfg.stats_interval)
        while True:
            await asyncio.sleep(interval)
            tx_rate = (self.tx_bytes - last_tx) / interval / 1024.0
            rx_rate = (self.rx_bytes - last_rx) / interval / 1024.0
            last_tx = self.tx_bytes
            last_rx = self.rx_bytes
            if (
                tx_rate > 0.05
                or rx_rate > 0.05
                or self.streams
                or self.dns_arq.has_pending_work()
            ):
                print(
                    f"[STATS] Carrier={self.active_carrier_label()} | "
                    f"Streams={len(self.streams)} | TX={tx_rate:.1f} KB/s | RX={rx_rate:.1f} KB/s | "
                    f"Q={self.dns_arq.queued_count()} Unacked={len(self.dns_arq.unacked)} | "
                    f"Batch={self.dns_arq.coalesced_packets} | ARQ-Retx={self.dns_arq.retransmit_count}"
                )

    async def run(self):
        if self.cfg.carrier_mode in ("all", "dns"):
            asyncio.create_task(self.maintain_dns_carrier())
        if self.cfg.carrier_mode in ("all", "udp"):
            asyncio.create_task(self.maintain_udp_carrier())
        if self.cfg.carrier_mode in ("all", "tcp"):
            asyncio.create_task(self.maintain_tcp_carrier())

        asyncio.create_task(self._monitor_stats())

        servers = []
        socks_server = await asyncio.start_server(
            self.inbound.handle_socks5_client, self.cfg.socks_host, self.cfg.socks_port
        )
        servers.append(socks_server)

        fwd_info = []
        if self.cfg.ssh_forward.strip():
            for rule in self.cfg.ssh_forward.split(","):
                rule = rule.strip()
                if "->" not in rule:
                    continue
                local_part, remote_part = rule.split("->", 1)
                l_host, l_port_s = local_part.rsplit(":", 1)
                fwd_srv = await asyncio.start_server(
                    lambda r, w, tgt=remote_part.strip(): self.inbound.handle_tcp_forward_client(
                        r, w, tgt
                    ),
                    l_host.strip(),
                    int(l_port_s.strip()),
                )
                servers.append(fwd_srv)
                fwd_info.append(f"{local_part.strip()}->{remote_part.strip()}")

        print(
            f"[{PROTOCOL_BANNER} CLIENT] SOCKS5={self.cfg.socks_host}:{self.cfg.socks_port} "
            f"| Forward={fwd_info if fwd_info else 'OFF'} "
            f"| Carrier={self.cfg.carrier_mode.upper()} | DNS={','.join(self.cfg.dns_resolvers)}:{self.cfg.dns_port} "
            f"| Workers={self.cfg.dns_workers} | QPS={self.cfg.dns_qps:.0f}..{self.cfg.dns_max_qps:.0f} "
            f"| Win={self.cfg.dns_inflight} | EDNS0={self.cfg.edns_size}B "
            f"| Verbose={'ON' if self.cfg.verbose else 'OFF'}"
        )
        await asyncio.gather(*(s.serve_forever() for s in servers))
