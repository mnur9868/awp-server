#!/usr/bin/env python3
import argparse
from dataclasses import asdict, dataclass, field
import json
from typing import List

# =====================================================================
# KONFIGURASI, PROFIL JSON & KONSTANTA PROTOKOL AWP v4.6
# =====================================================================
PROTOCOL_BANNER = "AWP-v4.6"
AWP_V3_SALT = b"AWP-V3-RAW-CUSTOM-2026"
WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Nilai Default Jaringan & Protokol
DEFAULT_CLIENT_REMOTE_HOST = "213.35.108.236"
DEFAULT_SERVER_BIND_HOST   = "0.0.0.0"
DEFAULT_MAIN_PORT          = 443
DEFAULT_EXTRA_PORTS        = "5353,2053,4500"
DEFAULT_JUMP_PORTS         = "53,443,4500,5353,2053"
DEFAULT_DNS_PORT           = 53
DEFAULT_DNS_ZONE           = "ns2.mnas.store"
DEFAULT_DNS_RESOLVERS      = "8.8.8.8,1.1.1.1"
DEFAULT_DNS_WORKERS        = 12
DEFAULT_DNS_QPS            = 32.0   # Total QPS gabungan (aman dari rate-limit ISP)
DEFAULT_DNS_MAX_QPS        = 48.0   # Batas atas AIMD saat 0 packet loss
DEFAULT_PSK                = "master-key-arul-v3-pure-2026"
DEFAULT_CARRIER_MODE       = "all"
DEFAULT_TCP_MIMIC          = "auto"
DEFAULT_WS_PATH            = "/ws"
DEFAULT_SOCKS_HOST         = "127.0.0.1"
DEFAULT_SOCKS_PORT         = 10808
DEFAULT_SSH_FORWARD        = "127.0.0.1:2222->127.0.0.1:22"

# Parameter Transport & Keandalan Pipelining
SESSION_TTL_SECONDS        = 300
FEC_GROUP_SIZE             = 4
DNS_MAX_UPLINK_CHUNK       = 68
DNS_MAX_DOWNLINK_CHUNK     = 540
DNS_LEGACY_DOWNLINK_CHUNK  = 205
DNS_MAX_INFLIGHT           = 36
DNS_BASE_RTO               = 1.25
EDNS0_UDP_PAYLOAD_SIZE     = 1232
EDNS0_LEGACY_PAYLOAD_SIZE  = 512

# Tipe Frame Internal
TYPE_SPA_HANDSHAKE = 0x01
TYPE_STREAM_OPEN   = 0x02
TYPE_STREAM_DATA   = 0x03
TYPE_STREAM_CLOSE  = 0x04
TYPE_FEC_PARITY    = 0x05
TYPE_HEARTBEAT     = 0x06
TYPE_DNS_POLL      = 0x07
TYPE_CARRIER_JUMP  = 0x08
TYPE_DNS_BATCH     = 0x09

# Flag Frame
FLAG_COMPRESSED  = 0x01
FLAG_KEY_RATCHET = 0x02
FLAG_UDP_CARRIER = 0x04
FLAG_DNS_CARRIER = 0x08

# ID Carrier Kriptografi
CARRIER_ID_TCP = 1
CARRIER_ID_UDP = 2
CARRIER_ID_DNS = 3


@dataclass
class AWPConfig:
    mode: str = "client"
    host: str = DEFAULT_CLIENT_REMOTE_HOST
    port: int = DEFAULT_MAIN_PORT
    extra_ports: List[int] = field(default_factory=lambda: [5353, 2053, 4500])
    jump_ports: List[int] = field(default_factory=lambda: [53, 443, 4500, 5353, 2053])
    jump_host: str = ""
    tcp_mimic: str = DEFAULT_TCP_MIMIC
    tls_sni: str = ""
    ws_path: str = DEFAULT_WS_PATH
    dns_resolvers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    dns_port: int = DEFAULT_DNS_PORT
    dns_zone: str = DEFAULT_DNS_ZONE
    dns_workers: int = DEFAULT_DNS_WORKERS
    dns_qps: float = DEFAULT_DNS_QPS
    dns_max_qps: float = DEFAULT_DNS_MAX_QPS
    dns_inflight: int = DNS_MAX_INFLIGHT
    dns_uplink_chunk: int = DNS_MAX_UPLINK_CHUNK
    dns_rto: float = DNS_BASE_RTO
    edns_size: int = EDNS0_LEGACY_PAYLOAD_SIZE
    psk: str = DEFAULT_PSK
    carrier_mode: str = DEFAULT_CARRIER_MODE
    socks_host: str = DEFAULT_SOCKS_HOST
    socks_port: int = DEFAULT_SOCKS_PORT
    ssh_forward: str = DEFAULT_SSH_FORWARD
    session_ttl: int = SESSION_TTL_SECONDS
    fec_group_size: int = FEC_GROUP_SIZE
    stats_interval: float = 10.0

    def save_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "AWPConfig":
        from slowdns import DnsCodec

        mode = "server" if args.server else "client"
        raw_cfg: dict = {}

        if args.config:
            with open(args.config, "r", encoding="utf-8") as f:
                raw_cfg = json.load(f)

        default_host = (
            DEFAULT_SERVER_BIND_HOST if mode == "server" else DEFAULT_CLIENT_REMOTE_HOST
        )
        host = (
            args.host
            if args.host is not None
            else raw_cfg.get("host", default_host)
        )

        if args.extra_ports is not None:
            extra_ports = [
                int(p.strip())
                for p in args.extra_ports.split(",")
                if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535
            ]
        else:
            extra_ports = raw_cfg.get("extra_ports", [5353, 2053, 4500])

        if args.jump_ports is not None:
            jump_ports = [
                int(p.strip())
                for p in args.jump_ports.split(",")
                if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535
            ]
        else:
            jump_ports = raw_cfg.get("jump_ports", [53, 443, 4500, 5353, 2053])

        if args.dns_server is not None:
            if args.dns_server.strip().lower() == "auto":
                sys_dns = DnsCodec.detect_system_dns_resolvers()
                for pub in ("8.8.8.8", "1.1.1.1"):
                    if pub not in sys_dns:
                        sys_dns.append(pub)
                dns_resolvers = sys_dns[:3]
            else:
                dns_resolvers = [
                    ip.strip() for ip in args.dns_server.split(",") if ip.strip()
                ] or ["8.8.8.8", "1.1.1.1"]
        elif "dns_resolvers" in raw_cfg:
            dns_resolvers = raw_cfg["dns_resolvers"]
        else:
            dns_resolvers = [ip.strip() for ip in DEFAULT_DNS_RESOLVERS.split(",")]

        ws_path = args.ws_path if args.ws_path is not None else raw_cfg.get("ws_path", DEFAULT_WS_PATH)
        if not ws_path.startswith("/"):
            ws_path = "/" + ws_path

        base_qps = args.dns_qps if args.dns_qps is not None else raw_cfg.get("dns_qps", DEFAULT_DNS_QPS)
        max_qps = (
            args.dns_max_qps
            if args.dns_max_qps is not None
            else raw_cfg.get("dns_max_qps", max(base_qps * 1.4, DEFAULT_DNS_MAX_QPS))
        )

        return cls(
            mode=mode,
            host=host,
            port=args.port if args.port is not None else raw_cfg.get("port", DEFAULT_MAIN_PORT),
            extra_ports=extra_ports,
            jump_ports=jump_ports,
            jump_host=(args.jump_host if args.jump_host is not None else raw_cfg.get("jump_host", "")).strip(),
            tcp_mimic=(args.tcp_mimic if args.tcp_mimic is not None else raw_cfg.get("tcp_mimic", DEFAULT_TCP_MIMIC)).lower(),
            tls_sni=(args.sni if args.sni is not None else raw_cfg.get("tls_sni", "")).strip(),
            ws_path=ws_path,
            dns_resolvers=dns_resolvers,
            dns_port=args.dns_port if args.dns_port is not None else raw_cfg.get("dns_port", DEFAULT_DNS_PORT),
            dns_zone=(args.dns_zone if args.dns_zone is not None else raw_cfg.get("dns_zone", DEFAULT_DNS_ZONE)).strip(),
            dns_workers=max(1, min(28, args.dns_workers if args.dns_workers is not None else raw_cfg.get("dns_workers", DEFAULT_DNS_WORKERS))),
            dns_qps=base_qps,
            dns_max_qps=max(base_qps, max_qps),
            dns_inflight=max(8, min(64, args.dns_inflight if args.dns_inflight is not None else raw_cfg.get("dns_inflight", DNS_MAX_INFLIGHT))),
            dns_uplink_chunk=max(32, min(96, args.dns_uplink_chunk if args.dns_uplink_chunk is not None else raw_cfg.get("dns_uplink_chunk", DNS_MAX_UPLINK_CHUNK))),
            dns_rto=max(0.7, min(5.0, args.dns_rto if args.dns_rto is not None else raw_cfg.get("dns_rto", DNS_BASE_RTO))),
            edns_size=args.edns_size if args.edns_size is not None else raw_cfg.get("edns_size", EDNS0_LEGACY_PAYLOAD_SIZE),
            psk=args.psk if args.psk is not None else raw_cfg.get("psk", DEFAULT_PSK),
            carrier_mode=(args.carrier if args.carrier is not None else raw_cfg.get("carrier_mode", DEFAULT_CARRIER_MODE)).lower(),
            socks_host=raw_cfg.get("socks_host", DEFAULT_SOCKS_HOST),
            socks_port=args.socks_port if args.socks_port is not None else raw_cfg.get("socks_port", DEFAULT_SOCKS_PORT),
            ssh_forward=args.ssh_forward if args.ssh_forward is not None else raw_cfg.get("ssh_forward", DEFAULT_SSH_FORWARD),
            session_ttl=raw_cfg.get("session_ttl", SESSION_TTL_SECONDS),
            fec_group_size=raw_cfg.get("fec_group_size", FEC_GROUP_SIZE),
            stats_interval=args.stats_interval if args.stats_interval is not None else raw_cfg.get("stats_interval", 10.0),
        )
