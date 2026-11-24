#!/usr/bin/env python3
from dataclasses import asdict, dataclass, field
import json
from typing import List


# =====================================================================
# KONSTANTA PROTOKOL & PARAMETER TUNING DNS-ARQ / MULTI-CARRIER
# =====================================================================
PROTOCOL_BANNER = "AWP-v4.7"
PROTOCOL_VERSION = 3

# Default Network & Auth
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 443
DEFAULT_DNS_PORT = 53
DEFAULT_DNS_ZONE = "ns2.mnas.store"
DEFAULT_PSK = "AWP-ULTRA-SECRET-KEY-2026"
DEFAULT_SOCKS_PORT = 10808
DEFAULT_EXTRA_PORTS = [5353, 2053, 4500]
DEFAULT_JUMP_PORTS = [53, 443, 4500, 5353, 2053]
DEFAULT_SESSION_TTL = 900

# Konstanta Kriptografi, SPA & Key Ratchet (crypto.py)
AWP_V3_SALT = b"AWP-V3-HKDF-SALT-2026"
AWP_SPA_SALT = b"AWP-V3-SPA-SALT-2026"
SPA_SALT = b"AWP-V3-SPA-SALT-2026"
AWP_RATCHET_SALT = b"AWP-V3-RATCHET-SALT-2026"
RATCHET_SALT = b"AWP-V3-RATCHET-SALT-2026"

SPA_WINDOW_SEC = 120
SPA_TOLERANCE_SEC = 120
SPA_TIME_STEP = 30
REPLAY_WINDOW_SIZE = 2048
COMPRESS_THRESHOLD = 128

KEY_RATCHET_INTERVAL = 512
RATCHET_INTERVAL = 512
RATCHET_PACKET_INTERVAL = 512
KEY_RATCHET_PACKETS = 512
KEY_RATCHET_BYTES = 1048576
RATCHET_BYTE_INTERVAL = 1048576

TOKEN_SIZE = 8
SPA_TOKEN_SIZE = 8
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = 17
FRAME_HEADER_SIZE = 17

# Carrier IDs & Frame Flags
CARRIER_ID_TCP = 1
CARRIER_ID_UDP = 2
CARRIER_ID_DNS = 3
CARRIER_ID_DOH = 4

FLAG_UDP_CARRIER = 0x01
FLAG_DNS_CARRIER = 0x02
FLAG_COMPRESSED = 0x04
FLAG_KEY_RATCHET = 0x08

# Frame Types
TYPE_STREAM_OPEN = 0x01
TYPE_STREAM_DATA = 0x02
TYPE_STREAM_CLOSE = 0x03
TYPE_HEARTBEAT = 0x04
TYPE_SPA_HANDSHAKE = 0x05
TYPE_FEC_PARITY = 0x06
TYPE_DNS_POLL = 0x07
TYPE_DNS_BATCH = 0x08
TYPE_CARRIER_JUMP = 0x09

# QUIC-UDP & FEC Constants (quic_udp.py)
FEC_GROUP_SIZE = 4
FEC_MAX_GROUPS = 64
FEC_WINDOW_SIZE = 64
FEC_HISTORY_SIZE = 64
QUIC_VERSION = 0x00000001
QUIC_DCID_LEN = 8
QUIC_SCID_LEN = 8

# Kamuflase TLS 1.3 Constants (tls.py)
DEFAULT_TLS_SNI = "www.cloudflare.com"
TLS_SNI_POOL = [
    "www.cloudflare.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "api.github.com",
]
TLS_SNI_CANDIDATES = TLS_SNI_POOL
TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_CCS = 0x14
TLS_RECORD_APP_DATA = 0x17
TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304
TLS_MAX_RECORD_SIZE = 16384

# Kamuflase WebSocket Constants (ws.py)
DEFAULT_WS_PATH = "/ws"
WS_DEFAULT_PATH = "/ws"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_MAX_FRAME_SIZE = 65536
WS_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]

# DNS QTYPE Constants & DoH Defaults
DNS_QTYPE_NULL = 10
DNS_QTYPE_TXT = 16
DNS_QTYPE_PRIVATE = 65399

DEFAULT_DOH_URLS = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
]

# Ukuran EDNS0 & Batas Chunk DNS-ARQ (Anti-Fragmentasi & Anti-Truncate)
EDNS0_LEGACY_PAYLOAD_SIZE = 512
EDNS0_UDP_PAYLOAD_SIZE = 1232

DNS_LEGACY_DOWNLINK_CHUNK = 205
DNS_MAX_DOWNLINK_CHUNK = 640
DNS_NULL_MAX_DOWNLINK_CHUNK = 920
DNS_MAX_UPLINK_CHUNK = 72
DNS_MAX_INFLIGHT = 48
DNS_BASE_RTO = 0.75
DNS_EDNS_RECOVERY_INTERVAL = 75.0


def _parse_int_list(raw: str, default: List[int]) -> List[int]:
    if not raw or not raw.strip():
        return list(default)
    out: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            val = int(part)
            if 1 <= val <= 65535 and val not in out:
                out.append(val)
    return out if out else list(default)


@dataclass
class AWPConfig:
    mode: str = "client"
    host: str = "0.0.0.0"
    port: int = 443
    dns_port: int = 53
    dns_zone: str = "ns2.mnas.store"
    psk: str = "AWP-ULTRA-SECRET-KEY-2026"
    verbose: bool = False

    # Server options
    extra_ports: List[int] = field(default_factory=lambda: [5353, 2053, 4500])
    jump_host: str = ""
    session_ttl: int = 900

    # Client options
    jump_ports: List[int] = field(default_factory=lambda: [53, 443, 4500, 5353, 2053])
    tcp_mimic: str = "auto"
    tls_sni: str = ""
    ws_path: str = "/ws"
    dns_resolvers: List[str] = field(
        default_factory=lambda: [
            "8.8.8.8",
            "1.1.1.1",
            "8.8.4.4",
            "1.0.0.1",
        ]
    )
    dns_qtype: str = "auto"  # auto | txt | null
    dns_0x20: bool = True
    doh_urls: List[str] = field(default_factory=lambda: list(DEFAULT_DOH_URLS))
    dns_workers: int = 12
    dns_qps: float = 34.0
    dns_max_qps: float = 56.0
    dns_inflight: int = DNS_MAX_INFLIGHT
    dns_uplink_chunk: int = DNS_MAX_UPLINK_CHUNK
    dns_rto: float = DNS_BASE_RTO
    edns_size: int = EDNS0_LEGACY_PAYLOAD_SIZE
    carrier_mode: str = "all"  # all | dns | doh | udp | tcp

    # Local inbounds & FEC
    socks_host: str = "127.0.0.1"
    socks_port: int = 10808
    ssh_forward: str = "127.0.0.1:2222->127.0.0.1:22"
    fec_group_size: int = 4
    stats_interval: float = 10.0

    def to_dict(self) -> dict:
        return asdict(self)

    def save_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_json(cls, path: str) -> "AWPConfig":
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        cfg = cls()
        for k, v in raw.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    @classmethod
    def from_args(cls, args) -> "AWPConfig":
        from slowdns import DnsCodec

        cfg = cls.from_json(args.config) if getattr(args, "config", None) else cls()
        cfg.mode = "server" if args.server else "client"

        if getattr(args, "verbose", False):
            cfg.verbose = True

        if args.host is not None:
            cfg.host = args.host
        elif cfg.mode == "client" and cfg.host == "0.0.0.0":
            cfg.host = "213.35.108.236"

        if args.port is not None:
            cfg.port = args.port
        if args.dns_port is not None:
            cfg.dns_port = args.dns_port
        if args.dns_zone is not None:
            cfg.dns_zone = args.dns_zone
        if args.psk is not None:
            cfg.psk = args.psk
        if args.extra_ports is not None:
            cfg.extra_ports = _parse_int_list(args.extra_ports, [5353, 2053, 4500])
        if args.jump_host is not None:
            cfg.jump_host = args.jump_host
        if args.jump_ports is not None:
            cfg.jump_ports = _parse_int_list(
                args.jump_ports, [53, 443, 4500, 5353, 2053]
            )
        if args.tcp_mimic is not None:
            cfg.tcp_mimic = args.tcp_mimic
        if args.sni is not None:
            cfg.tls_sni = args.sni
        if args.ws_path is not None:
            cfg.ws_path = args.ws_path

        if args.dns_server is not None:
            if args.dns_server.strip().lower() == "auto":
                cfg.dns_resolvers = DnsCodec.detect_system_dns_resolvers()
            else:
                parsed = [
                    x.strip() for x in args.dns_server.split(",") if x.strip()
                ]
                if parsed:
                    cfg.dns_resolvers = parsed
        elif not getattr(args, "config", None):
            cfg.dns_resolvers = DnsCodec.detect_system_dns_resolvers()

        if getattr(args, "dns_qtype", None) is not None:
            cfg.dns_qtype = args.dns_qtype.lower()
        if getattr(args, "no_dns_0x20", False):
            cfg.dns_0x20 = False
        if getattr(args, "doh_url", None) is not None:
            urls = [u.strip() for u in args.doh_url.split(",") if u.strip()]
            if urls:
                cfg.doh_urls = urls

        if args.dns_workers is not None:
            cfg.dns_workers = max(1, min(64, args.dns_workers))
        if args.dns_qps is not None:
            cfg.dns_qps = max(8.0, min(200.0, args.dns_qps))
        if args.dns_max_qps is not None:
            cfg.dns_max_qps = max(cfg.dns_qps, min(250.0, args.dns_max_qps))
        if args.dns_inflight is not None:
            cfg.dns_inflight = max(8, min(64, args.dns_inflight))
        if args.dns_uplink_chunk is not None:
            cfg.dns_uplink_chunk = max(28, min(110, args.dns_uplink_chunk))
        if args.dns_rto is not None:
            cfg.dns_rto = max(0.35, min(5.0, args.dns_rto))
        if args.edns_size is not None:
            cfg.edns_size = args.edns_size
        if args.carrier is not None:
            cfg.carrier_mode = args.carrier
        if args.socks_port is not None:
            cfg.socks_port = args.socks_port
        if args.ssh_forward is not None:
            cfg.ssh_forward = args.ssh_forward
        if args.stats_interval is not None:
            cfg.stats_interval = max(1.0, args.stats_interval)

        return cfg
