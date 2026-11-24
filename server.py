#!/usr/bin/env python3
import asyncio
import base64
from datetime import datetime
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
    EDNS0_UDP_PAYLOAD_SIZE,
    FLAG_DNS_CARRIER,
    FLAG_UDP_CARRIER,
    PROTOCOL_BANNER,
    TYPE_CARRIER_JUMP,
    TYPE_DNS_BATCH,
    TYPE_DNS_POLL,
    TYPE_FEC_PARITY,
    TYPE_HEARTBEAT,
    TYPE_SPA_HANDSHAKE,
    TYPE_STREAM_CLOSE,
    TYPE_STREAM_DATA,
    TYPE_STREAM_OPEN,
)
from crypto import AWPv3Crypto
from quic_udp import FecEngine
from slowdns import DnsArqEngine


def _vts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


# =====================================================================
# SERVER ENGINE & MULTI-CARRIER LISTENERS
# =====================================================================
class AWPServerSession:
    def __init__(self, token: bytes, cfg: AWPConfig, advertised_endpoints: List[str]):
        self.token = token
        self.cfg = cfg
        self.advertised_endpoints = advertised_endpoints

        self.tcp_crypto = AWPv3Crypto(cfg.psk, token, CARRIER_ID_TCP, is_server=True, ordered=True)
        self.udp_crypto = AWPv3Crypto(cfg.psk, token, CARRIER_ID_UDP, is_server=True, ordered=False)
        self.dns_crypto = AWPv3Crypto(cfg.psk, token, CARRIER_ID_DNS, is_server=True, ordered=False)

        self.dns_arq = DnsArqEngine(
            self.dns_crypto,
            is_server=True,
            initial_edns=EDNS0_UDP_PAYLOAD_SIZE,
            max_inflight=cfg.dns_inflight,
            base_rto=cfg.dns_rto,
            verbose=cfg.verbose,
        )
        self.udp_fec = FecEngine(cfg.fec_group_size)

        self.tcp_writer: Optional[asyncio.StreamWriter] = None
        self.tcp_framing: str = "tls"
        self.tcp_verified = False
        self.tcp_lock = asyncio.Lock()
        self.tcp_last_seen = 0.0

        self.udp_addr: Optional[Tuple[str, int]] = None
        self.udp_transport: Optional[asyncio.DatagramTransport] = None
        self.udp_verified = False
        self.udp_last_seen = 0.0

        self.dns_last_seen = 0.0
        self.dns_prev_query_ts = 0.0
        self.jump_hint_sent = False
        self.last_active = time.time()

        self.streams: Dict[int, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.stream_pending_tx: Dict[int, list] = {}

    def touch(self):
        self.last_active = time.time()

    def has_fast_carrier(self) -> bool:
        now = time.time()
        udp_ok = (
            self.udp_verified
            and self.udp_transport is not None
            and self.udp_addr is not None
            and (now - self.udp_last_seen < 25.0)
        )
        tcp_ok = (
            self.tcp_verified
            and self.tcp_writer is not None
            and not self.tcp_writer.is_closing()
        )
        return udp_ok or tcp_ok

    def is_dns_active(self) -> bool:
        return (time.time() - self.dns_last_seen) < 45.0

    def push_jump_hint_once(self):
        if self.jump_hint_sent or not self.advertised_endpoints:
            return
        self.jump_hint_sent = True
        hint_blob = ",".join(self.advertised_endpoints).encode("utf-8")
        self.dns_arq.enqueue(TYPE_CARRIER_JUMP, 0, hint_blob)

    async def send_downlink(self, frame_type: int, stream_id: int, payload: bytes = b""):
        now = time.time()
        if (
            self.udp_verified
            and self.udp_transport
            and self.udp_addr
            and (now - self.udp_last_seen < 25.0)
        ):
            try:
                wire_pkt, seq_num, clean_frame = self.udp_crypto.encode_frame(
                    frame_type, stream_id, payload, flags=FLAG_UDP_CARRIER
                )
                self.udp_transport.sendto(
                    CamouflageCodec.wrap_quic_mimic(wire_pkt, is_initial=False),
                    self.udp_addr,
                )
                if frame_type == TYPE_STREAM_DATA:
                    parity_blob = self.udp_fec.build_tx_parity_if_ready(seq_num, clean_frame)
                    if parity_blob:
                        fec_wire, _, _ = self.udp_crypto.encode_frame(
                            TYPE_FEC_PARITY, 0, parity_blob, flags=FLAG_UDP_CARRIER
                        )
                        self.udp_transport.sendto(
                            CamouflageCodec.wrap_quic_mimic(fec_wire, is_initial=False),
                            self.udp_addr,
                        )
                return
            except Exception:
                self.udp_verified = False

        if self.tcp_verified and self.tcp_writer and not self.tcp_writer.is_closing():
            try:
                async with self.tcp_lock:
                    wire_pkt, _, _ = self.tcp_crypto.encode_frame(
                        frame_type, stream_id, payload
                    )
                    framed = CamouflageCodec.wrap_tcp_stream_frame(
                        self.tcp_framing, wire_pkt, is_client=False
                    )
                    self.tcp_writer.write(framed)
                    await self.tcp_writer.drain()
                return
            except Exception:
                self.tcp_verified = False

        if self.is_dns_active():
            self.dns_arq.enqueue(frame_type, stream_id, payload)


class _ServerUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: "AWPServerNode", bind_port: int):
        self.node = node
        self.bind_port = bind_port
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.logged_peers: set = set()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if self.transport:
            self.node.on_udp_datagram(data, addr, self.transport, self.bind_port, self.logged_peers)


class _ServerDNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: "AWPServerNode"):
        self.node = node
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if self.transport:
            self.node.on_dns_datagram(data, addr, self.transport)


class AWPServerNode:
    def __init__(self, cfg: AWPConfig):
        self.cfg = cfg
        self.sessions: Dict[bytes, AWPServerSession] = {}
        self.zone_labels = [lbl.lower() for lbl in cfg.dns_zone.strip(".").split(".") if lbl]
        self.advertised_endpoints: List[str] = []

    def _vlog(self, msg: str):
        if self.cfg.verbose:
            print(f"[{_vts()}][VERBOSE][SRV] {msg}")

    def get_or_create_session(self, token: bytes) -> Tuple[AWPServerSession, bool]:
        if token in self.sessions:
            sess = self.sessions[token]
            sess.touch()
            return sess, False
        sess = AWPServerSession(token, self.cfg, self.advertised_endpoints)
        self.sessions[token] = sess
        return sess, True

    async def _pipe_target_to_client(
        self, session: AWPServerSession, stream_id: int, target_reader: asyncio.StreamReader
    ):
        tok = session.token.hex()[:8]
        total_rx = 0
        try:
            while True:
                if not session.has_fast_carrier():
                    while session.dns_arq.queued_count() > 320:
                        if stream_id not in session.streams or session.has_fast_carrier():
                            break
                        await asyncio.sleep(0.006)

                read_sz = (
                    32768
                    if session.has_fast_carrier()
                    else (session.dns_arq.downlink_chunk_limit() * 16)
                )
                data = await target_reader.read(read_sz)
                if not data or stream_id not in session.streams:
                    self._vlog(
                        f"[{tok}] SID={stream_id} target EOF (total_downlink={total_rx}B, "
                        f"arq_q={session.dns_arq.queued_count()}, unacked={len(session.dns_arq.unacked)})"
                    )
                    break
                total_rx += len(data)
                session.touch()
                self._vlog(
                    f"[{tok}] SID={stream_id} target->client {len(data)}B (total={total_rx}B)"
                )
                await session.send_downlink(TYPE_STREAM_DATA, stream_id, data)
        except Exception as e:
            self._vlog(f"[{tok}] SID={stream_id} target read error: {type(e).__name__}: {e}")
        finally:
            was_open = stream_id in session.streams
            if was_open:
                _, w = session.streams.pop(stream_id)
                try:
                    w.close()
                except Exception:
                    pass
            session.stream_pending_tx.pop(stream_id, None)
            if was_open:
                self._vlog(f"[{tok}] SID={stream_id} enqueue STREAM_CLOSE")
                try:
                    await session.send_downlink(TYPE_STREAM_CLOSE, stream_id, b"")
                except Exception:
                    pass

    async def _open_target_stream(self, session: AWPServerSession, stream_id: int, target: str):
        tok = session.token.hex()[:8]
        if ":" not in target:
            session.stream_pending_tx.pop(stream_id, None)
            self._vlog(f"[{tok}] SID={stream_id} invalid target='{target}'")
            return
        host, port_s = target.rsplit(":", 1)
        self._vlog(f"[{tok}] SID={stream_id} connecting TCP -> {host}:{port_s}")
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port_s)), timeout=10.0
            )
            sock = t_writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            flushed = 0
            while True:
                pending = session.stream_pending_tx.get(stream_id)
                if not pending:
                    session.stream_pending_tx.pop(stream_id, None)
                    session.streams[stream_id] = (t_reader, t_writer)
                    break
                batch = list(pending)
                pending.clear()
                for item in batch:
                    if item is None:
                        session.stream_pending_tx.pop(stream_id, None)
                        t_writer.close()
                        self._vlog(f"[{tok}] SID={stream_id} closed while connecting")
                        return
                    t_writer.write(item)
                    flushed += len(item)
                await t_writer.drain()

            self._vlog(
                f"[{tok}] SID={stream_id} CONNECTED -> {host}:{port_s} (flushed={flushed}B)"
            )
            asyncio.create_task(self._pipe_target_to_client(session, stream_id, t_reader))
        except Exception as e:
            session.stream_pending_tx.pop(stream_id, None)
            self._vlog(
                f"[{tok}] SID={stream_id} CONNECT FAIL -> {host}:{port_s}: {type(e).__name__}: {e}"
            )
            await session.send_downlink(TYPE_STREAM_CLOSE, stream_id, b"FAIL")

    async def _execute_stream_action(
        self, session: AWPServerSession, ftype: int, stream_id: int, payload: bytes
    ):
        tok = session.token.hex()[:8]
        if ftype == TYPE_STREAM_OPEN:
            target = payload.decode("utf-8", errors="ignore")
            self._vlog(f"[{tok}] RX STREAM_OPEN SID={stream_id} target={target}")
            session.stream_pending_tx[stream_id] = []
            asyncio.create_task(self._open_target_stream(session, stream_id, target))
        elif ftype == TYPE_STREAM_DATA:
            if stream_id in session.streams:
                _, t_writer = session.streams[stream_id]
                try:
                    t_writer.write(payload)
                    await t_writer.drain()
                    self._vlog(f"[{tok}] RX STREAM_DATA SID={stream_id} -> target {len(payload)}B")
                except Exception as e:
                    self._vlog(f"[{tok}] SID={stream_id} target write err: {e}")
                    session.streams.pop(stream_id, None)
            elif stream_id in session.stream_pending_tx:
                session.stream_pending_tx[stream_id].append(payload)
                self._vlog(
                    f"[{tok}] RX STREAM_DATA SID={stream_id} buffered {len(payload)}B (connecting)"
                )
            else:
                self._vlog(
                    f"[{tok}] RX STREAM_DATA SID={stream_id} ignored ({len(payload)}B, stream closed)"
                )
        elif ftype == TYPE_STREAM_CLOSE:
            self._vlog(f"[{tok}] RX STREAM_CLOSE SID={stream_id}")
            session.dns_arq.purge_stream(stream_id)
            if stream_id in session.streams:
                _, t_writer = session.streams.pop(stream_id)
                try:
                    t_writer.close()
                except Exception:
                    pass
            elif stream_id in session.stream_pending_tx:
                session.stream_pending_tx[stream_id].append(None)
        elif ftype == TYPE_HEARTBEAT:
            await session.send_downlink(TYPE_HEARTBEAT, 0, payload)

    async def dispatch_frame(
        self, session: AWPServerSession, frame: dict, source_carrier: str
    ):
        session.touch()
        ftype = frame["type"]
        stream_id = frame["stream_id"]
        payload = frame["payload"]

        if source_carrier == "dns":
            await session.dns_arq.ingest_incoming(
                payload,
                lambda t, s, d: self._execute_stream_action(session, t, s, d),
                token_hex=session.token.hex(),
            )
            return

        if source_carrier == "udp":
            is_dup, recovered = session.udp_fec.process_rx_frame(frame)
            if not is_dup:
                await self._execute_stream_action(session, ftype, stream_id, payload)
            if recovered:
                await self._execute_stream_action(
                    session, recovered["type"], recovered["stream_id"], recovered["payload"]
                )
            return

        await self._execute_stream_action(session, ftype, stream_id, payload)

    def on_udp_datagram(
        self,
        data: bytes,
        addr: Tuple[str, int],
        transport: asyncio.DatagramTransport,
        bind_port: int,
        logged_peers: set,
    ):
        unwrapped = CamouflageCodec.unwrap_quic_mimic(data)
        spa = CamouflageCodec.verify_spa_packet(self.cfg.psk, unwrapped)
        if spa is not None:
            token, _ = spa
            sess, _ = self.get_or_create_session(token)
            sess.udp_addr = addr
            sess.udp_transport = transport
            sess.udp_verified = False
            key = (token, bind_port, addr)
            if key not in logged_peers:
                logged_peers.add(key)
                print(
                    f"[{PROTOCOL_BANNER}] QUIC-UDP SPA PROBE (Port {bind_port}) "
                    f"| Token={token.hex()} | Peer={addr}"
                )
            ack_wire, _, _ = sess.udp_crypto.encode_frame(
                TYPE_SPA_HANDSHAKE, 0, b"V3-UDP-OK", flags=FLAG_UDP_CARRIER
            )
            transport.sendto(CamouflageCodec.wrap_quic_mimic(ack_wire, is_initial=False), addr)
            return

        token = CamouflageCodec.extract_stateless_session_token(self.cfg.psk, unwrapped)
        if not token or token not in self.sessions:
            return
        sess = self.sessions[token]
        try:
            frame = sess.udp_crypto.decode_frame(unwrapped)
            if not sess.udp_verified:
                sess.udp_verified = True
                print(
                    f"[{PROTOCOL_BANNER}] QUIC-UDP JUMP VERIFIED! (Port {bind_port}) "
                    f"| Token={token.hex()} | Peer={addr}"
                )
            sess.udp_addr = addr
            sess.udp_transport = transport
            sess.udp_last_seen = time.time()
            asyncio.create_task(self.dispatch_frame(sess, frame, source_carrier="udp"))
        except Exception as e:
            self._vlog(f"UDP decode error from {addr}: {e}")

    @staticmethod
    def _calc_safe_downlink_arq_budget(edns_size: int, question_len: int) -> int:
        if edns_size <= EDNS0_LEGACY_PAYLOAD_SIZE:
            # 12B DNS hdr + question + 12B RR hdr = 24 + question_len; total <= 496B
            # Mencegah TC=1 truncation pada resolver seperti 8.8.4.4
            max_rdata = max(64, 496 - (24 + question_len))
            max_b64 = (max_rdata * 250) // 251
            max_ctrl_wire = (max_b64 * 3) // 4
            # -2B control hdr, -49B AWP crypto envelope
            return max(48, max_ctrl_wire - 51)
        # 12B DNS hdr + question + 12B RR hdr + 11B OPT RR = 35 + question_len
        safe_udp_cap = max(512, edns_size - 16)
        max_rdata = max(128, safe_udp_cap - (35 + question_len))
        max_b64 = (max_rdata * 250) // 251
        max_ctrl_wire = (max_b64 * 3) // 4
        hard_cap = (
            DnsArqEngine.ARQ_HDR_SIZE
            + DnsArqEngine.SUB_HDR_SIZE
            + DNS_MAX_DOWNLINK_CHUNK
        )
        return max(48, min(hard_cap, max_ctrl_wire - 51))

    def on_dns_datagram(
        self, data: bytes, addr: Tuple[str, int], transport: asyncio.DatagramTransport
    ):
        # Mode 1: Direct QUIC-UDP pada port 53
        unwrapped = CamouflageCodec.unwrap_quic_mimic(data)
        raw_spa = CamouflageCodec.verify_spa_packet(self.cfg.psk, unwrapped)
        if raw_spa is not None and raw_spa[1] == CARRIER_ID_UDP:
            token, _ = raw_spa
            sess, is_new = self.get_or_create_session(token)
            sess.udp_addr = addr
            sess.udp_transport = transport
            sess.udp_verified = False
            if is_new:
                print(
                    f"[{PROTOCOL_BANNER}] DIRECT-UDP-53 SPA PROBE | Token={token.hex()} | Peer={addr}"
                )
            ack_wire, _, _ = sess.udp_crypto.encode_frame(
                TYPE_SPA_HANDSHAKE, 0, b"V3-UDP-OK", flags=FLAG_UDP_CARRIER
            )
            transport.sendto(CamouflageCodec.wrap_quic_mimic(ack_wire, is_initial=False), addr)
            return

        raw_token = CamouflageCodec.extract_stateless_session_token(self.cfg.psk, unwrapped)
        if raw_token and raw_token in self.sessions:
            sess = self.sessions[raw_token]
            try:
                frame = sess.udp_crypto.decode_frame(unwrapped)
                if not sess.udp_verified:
                    sess.udp_verified = True
                    print(
                        f"[{PROTOCOL_BANNER}] DIRECT-UDP-53 JUMP VERIFIED! "
                        f"| Token={raw_token.hex()} | Peer={addr}"
                    )
                sess.udp_addr = addr
                sess.udp_transport = transport
                sess.udp_last_seen = time.time()
                asyncio.create_task(self.dispatch_frame(sess, frame, source_carrier="udp"))
                return
            except Exception:
                pass

        # Mode 2: Authoritative DNS Tunnel
        parsed = CamouflageCodec.parse_dns_query(data)
        if not parsed:
            return
        tx_id, labels, question_wire, qtype, _, edns_udp_size = parsed
        lower_labels = [lbl.lower() for lbl in labels]
        zlen = len(self.zone_labels)
        if len(lower_labels) <= zlen or lower_labels[-zlen:] != self.zone_labels:
            return

        b32_str = "".join(labels[:-zlen]).upper()
        pad_needed = (8 - (len(b32_str) % 8)) % 8
        try:
            wire_bytes = base64.b32decode(b32_str + ("=" * pad_needed))
        except Exception:
            self._vlog(f"DNS base32 decode fail from {addr}")
            return

        spa = CamouflageCodec.verify_spa_packet(self.cfg.psk, wire_bytes)
        if spa is not None:
            token, _ = spa
            sess, is_new = self.get_or_create_session(token)
            sess.dns_last_seen = time.time()
            sess.dns_prev_query_ts = time.monotonic()
            if 0 < edns_udp_size <= EDNS0_LEGACY_PAYLOAD_SIZE:
                sess.dns_arq.edns_size = EDNS0_LEGACY_PAYLOAD_SIZE
                sess.dns_arq.client_chunk_cap = DNS_LEGACY_DOWNLINK_CHUNK
            elif (
                edns_udp_size > EDNS0_LEGACY_PAYLOAD_SIZE
                and sess.dns_arq.client_chunk_cap > DNS_LEGACY_DOWNLINK_CHUNK
            ):
                sess.dns_arq.edns_size = edns_udp_size
            sess.push_jump_hint_once()

            print(
                f"[{PROTOCOL_BANNER}] DNS-JUMPER SPA {'NEW' if is_new else 'ATTACH'} "
                f"| Token={token.hex()} | Resolver={addr} | QTYPE={qtype} "
                f"| EDNS0={sess.dns_arq.edns_size}B"
            )
            ack_wire, _, _ = sess.dns_crypto.encode_frame(
                TYPE_SPA_HANDSHAKE, 0, b"V3-DNS-OK", flags=FLAG_DNS_CARRIER, min_pad=1, max_pad=1
            )
            resp = CamouflageCodec.build_dns_txt_response(
                tx_id,
                question_wire,
                ack_wire,
                has_more=sess.dns_arq.can_send_more(),
                backlog_hint=min(255, sess.dns_arq.queued_count()),
                edns_udp_size=sess.dns_arq.edns_size,
            )
            transport.sendto(resp, addr)
            return

        token = CamouflageCodec.extract_stateless_session_token(self.cfg.psk, wire_bytes)
        if not token or token not in self.sessions:
            self._vlog(f"DNS query unknown/expired token from {addr} (tx={tx_id})")
            return

        sess = self.sessions[token]
        tok = token.hex()[:8]
        try:
            frame = sess.dns_crypto.decode_frame(wire_bytes)
            now_mono = time.monotonic()
            if sess.dns_prev_query_ts > 0.0 and sess.dns_arq.unacked:
                oldest_tx = min(e[0] for e in sess.dns_arq.unacked.values() if e[0] > 0.0)
                if oldest_tx > 0.0:
                    est_rtt_ms = (now_mono - oldest_tx) * 1000.0
                    if 25.0 <= est_rtt_ms <= 1500.0:
                        sess.dns_arq.update_rtt_ms(est_rtt_ms)
            sess.dns_prev_query_ts = now_mono
            sess.dns_last_seen = time.time()

            if 0 < edns_udp_size <= EDNS0_LEGACY_PAYLOAD_SIZE:
                sess.dns_arq.apply_peer_cap_code(1, token.hex())

            hdr = sess.dns_arq.peek_ack_header(frame["payload"])
            peer_ack = 0
            peer_sack = 0
            peer_cap = 0
            if hdr is not None:
                peer_ack, peer_sack, _, peer_cap = hdr
                sess.dns_arq.apply_peer_cap_code(peer_cap, token.hex())
                sess.dns_arq.process_peer_ack(peer_ack, peer_sack)

            asyncio.create_task(self.dispatch_frame(sess, frame, source_carrier="dns"))

            budget = self._calc_safe_downlink_arq_budget(
                sess.dns_arq.edns_size, len(question_wire)
            )
            next_wire, has_more = sess.dns_arq.pop_next_wire(
                emit_idle_poll=False, max_arq_bytes_override=budget
            )
            backlog_total = min(255, sess.dns_arq.queued_count() + len(sess.dns_arq.unacked))
            resp = CamouflageCodec.build_dns_txt_response(
                tx_id,
                question_wire,
                next_wire,
                has_more=has_more,
                backlog_hint=backlog_total,
                edns_udp_size=sess.dns_arq.edns_size,
            )
            if self.cfg.verbose and (
                frame["type"] in (TYPE_DNS_BATCH, TYPE_DNS_POLL)
                or len(next_wire) > 0
                or sess.dns_arq.unacked
                or sess.dns_arq.queued_count() > 0
            ):
                self._vlog(
                    f"[{tok}] DNS tx={tx_id} res={addr[0]} in_type=0x{frame['type']:02x} "
                    f"in_len={len(frame['payload'])}B ack={peer_ack} sack=0x{peer_sack:x} cap={peer_cap} -> "
                    f"out_wire={len(next_wire)}B udp_len={len(resp)}B more={int(has_more)} "
                    f"q={sess.dns_arq.queued_count()} unacked={len(sess.dns_arq.unacked)} "
                    f"rto={sess.dns_arq.current_rto():.2f}s"
                )
            transport.sendto(resp, addr)
        except Exception as e:
            self._vlog(f"[{tok}] DNS decode/process err from {addr}: {type(e).__name__}: {e}")

    async def handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        peer = writer.get_extra_info("peername")
        sockname = writer.get_extra_info("sockname")
        local_port = sockname[1] if sockname else 0
        session: Optional[AWPServerSession] = None
        try:
            hdr4 = await asyncio.wait_for(reader.readexactly(4), timeout=8.0)

            if hdr4[0] == 0x16 and hdr4[1] == 0x03:
                framing_mode = "tls"
                label = "TLS1.3-TCP"
                b5 = await asyncio.wait_for(reader.readexactly(1), timeout=4.0)
                rec_len = struct.unpack("!H", hdr4[3:4] + b5)[0]
                if rec_len < 44 or rec_len > 4096:
                    return
                hs_payload = await asyncio.wait_for(reader.readexactly(rec_len), timeout=5.0)
                probe_valid = CamouflageCodec.extract_spa_from_tls_client_hello(
                    self.cfg.psk, hs_payload
                )
                if probe_valid is None:
                    return
                token, _ = probe_valid
                ws_key = ""
            elif hdr4 == b"GET ":
                framing_mode = "ws"
                label = "WS-HTTP"
                rest_hdr = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=5.0
                )
                if len(rest_hdr) > 8192:
                    return
                ws_parsed = CamouflageCodec.parse_ws_upgrade_request(
                    self.cfg.psk, hdr4 + rest_hdr
                )
                if ws_parsed is None:
                    return
                token, _, ws_key = ws_parsed
            else:
                return

            session, is_new = self.get_or_create_session(token)
            if session.tcp_writer and session.tcp_writer is not writer:
                try:
                    session.tcp_writer.close()
                except Exception:
                    pass

            session.tcp_crypto = AWPv3Crypto(
                self.cfg.psk, token, CARRIER_ID_TCP, is_server=True, ordered=True
            )
            session.tcp_writer = writer
            session.tcp_framing = framing_mode
            session.tcp_verified = False

            print(
                f"[{PROTOCOL_BANNER}] {label} SPA {'NEW' if is_new else 'ATTACH'} "
                f"(Port {local_port}) | Token={token.hex()} | Peer={peer}"
            )

            ack_wire, _, _ = session.tcp_crypto.encode_frame(
                TYPE_SPA_HANDSHAKE, 0, b"V3-TCP-OK"
            )
            async with session.tcp_lock:
                if framing_mode == "ws":
                    writer.write(CamouflageCodec.build_ws_upgrade_response(ws_key, ack_wire))
                else:
                    writer.write(CamouflageCodec.build_tls_server_hello_with_ack(ack_wire))
                await writer.drain()

            while True:
                rec_body = await CamouflageCodec.read_tcp_stream_frame(framing_mode, reader)
                frame = session.tcp_crypto.decode_frame(rec_body)
                if not session.tcp_verified:
                    session.tcp_verified = True
                    print(
                        f"[{PROTOCOL_BANNER}] {label} JUMP VERIFIED! (Port {local_port}) "
                        f"| Token={token.hex()} | Peer={peer}"
                    )
                session.tcp_last_seen = time.time()
                await self.dispatch_frame(session, frame, source_carrier="tcp")
        except Exception as e:
            self._vlog(f"TCP client {peer} closed: {type(e).__name__}: {e}")
        finally:
            if session and session.tcp_writer is writer:
                session.tcp_writer = None
                session.tcp_verified = False
            try:
                writer.close()
            except Exception:
                pass

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(60)
            now = time.time()
            expired = [
                tok
                for tok, s in self.sessions.items()
                if now - s.last_active > self.cfg.session_ttl
            ]
            for tok in expired:
                sess = self.sessions.pop(tok, None)
                if sess:
                    for _, (_, w) in sess.streams.items():
                        try:
                            w.close()
                        except Exception:
                            pass
                    if sess.tcp_writer:
                        try:
                            sess.tcp_writer.close()
                        except Exception:
                            pass
                    print(f"[{PROTOCOL_BANNER}] Session EXPIRED ({tok.hex()})")

    async def run(self):
        all_ports = [self.cfg.port] + [
            p for p in self.cfg.extra_ports if p != self.cfg.port
        ]
        loop = asyncio.get_running_loop()
        tcp_servers = []
        udp_transports = []
        active_ports = []

        for p in all_ports:
            try:
                srv = await asyncio.start_server(
                    self.handle_tcp_client, self.cfg.host, p
                )
                udp_tr, _ = await loop.create_datagram_endpoint(
                    lambda port=p: _ServerUDPProtocol(self, port),
                    local_addr=(self.cfg.host, p),
                )
                tcp_servers.append(srv)
                udp_transports.append(udp_tr)
                active_ports.append(p)
            except Exception as e:
                print(f"[{PROTOCOL_BANNER}] Info: port {p} dilewati ({e})")

        dns_transport, _ = await loop.create_datagram_endpoint(
            lambda: _ServerDNSProtocol(self),
            local_addr=(self.cfg.host, self.cfg.dns_port),
        )

        adv_ports = [self.cfg.dns_port] + active_ports
        self.advertised_endpoints = [
            f"{self.cfg.jump_host}:{p}" if self.cfg.jump_host else f":{p}"
            for p in adv_ports
        ]

        print(
            f"[{PROTOCOL_BANNER} SERVER] Aktif pada {self.cfg.host} Ports={active_ports} "
            f"[TLS1.3-TCP + WS-HTTP + QUIC-UDP] & UDP:{self.cfg.dns_port} "
            f"[DNS-JUMPER TLP SACK | Zone={self.cfg.dns_zone} | Verbose={'ON' if self.cfg.verbose else 'OFF'}]"
        )
        asyncio.create_task(self._cleanup_loop())

        try:
            await asyncio.gather(*(srv.serve_forever() for srv in tcp_servers))
        finally:
            for tr in udp_transports:
                tr.close()
            dns_transport.close()
