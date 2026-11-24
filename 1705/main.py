#!/usr/bin/env python3
import argparse
import asyncio

from client import AWPClientNode
from config import AWPConfig, PROTOCOL_BANNER
from server import AWPServerNode


# =====================================================================
# UNIFIED CLI ENTRYPOINT (--server / --client / --config / --verbose)
# =====================================================================
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{PROTOCOL_BANNER} Unified Multi-Carrier Tunnel (TLP, Multi-QTYPE DNS-ARQ & DoH)"
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--server", action="store_true", help="Jalankan sebagai Server di VPS"
    )
    mode_group.add_argument(
        "--client", action="store_true", help="Jalankan sebagai Client di perangkat lokal"
    )

    # Profil Konfigurasi JSON & Verbose
    parser.add_argument(
        "--config",
        default=None,
        help="Muat profil konfigurasi dari file JSON",
    )
    parser.add_argument(
        "--gen-config",
        default=None,
        help="Simpan konfigurasi aktif ke file JSON lalu keluar",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Aktifkan log debug detail (paket DNS/DoH, stream, ARQ, dan timeout)",
    )

    # Opsi Umum (Server & Client)
    parser.add_argument(
        "--host",
        default=None,
        help="Server: IP bind (default 0.0.0.0) | Client: IP/Domain VPS tujuan",
    )
    parser.add_argument(
        "--port", type=int, default=None, help="Port utama TCP/UDP (default: 443)"
    )
    parser.add_argument(
        "--dns-port", type=int, default=None, help="Port DNS (default: 53)"
    )
    parser.add_argument(
        "--dns-zone", default=None, help="Zona NS delegasi DNS (default: ns2.mnas.store)"
    )
    parser.add_argument("--psk", default=None, help="Pre-Shared Key protokol")

    # Opsi Khusus Server
    parser.add_argument(
        "--extra-ports",
        default=None,
        help="[Server] Port tambahan TCP/UDP (default: 5353,2053,4500)",
    )
    parser.add_argument(
        "--jump-host",
        default=None,
        help="[Server] IP/Domain publik opsional untuk diiklankan DNS Jumper",
    )

    # Opsi Khusus Client
    parser.add_argument(
        "--jump-ports",
        default=None,
        help="[Client] Port kandidat loncatan cepat (default: 53,443,4500,5353,2053)",
    )
    parser.add_argument(
        "--tcp-mimic",
        choices=["auto", "tls", "ws"],
        default=None,
        help="[Client] Mode kamuflase TCP: auto, tls, atau ws (default: auto)",
    )
    parser.add_argument(
        "--sni",
        default=None,
        help="[Client] SNI TLS / Host header WebSocket opsional",
    )
    parser.add_argument(
        "--ws-path",
        default=None,
        help="[Client] Path URI WebSocket untuk mode ws/auto (default: /ws)",
    )
    parser.add_argument(
        "--dns-server",
        default=None,
        help="[Client] Resolver DNS UDP, misal 8.8.8.8,1.1.1.1 atau auto",
    )
    parser.add_argument(
        "--dns-qtype",
        choices=["auto", "txt", "null"],
        default=None,
        help="[Client] Tipe record DNS: auto (probing NULL->TXT), txt, atau null (default: auto)",
    )
    parser.add_argument(
        "--no-dns-0x20",
        action="store_true",
        help="[Client] Nonaktifkan pengacakan huruf besar/kecil DNS 0x20 anti-cache",
    )
    parser.add_argument(
        "--doh-url",
        default=None,
        help="[Client] Endpoint DNS-over-HTTPS RFC 8484 dipisah koma (default: dns.google,cloudflare-dns.com)",
    )
    parser.add_argument(
        "--dns-workers",
        type=int,
        default=None,
        help="[Client] Jumlah worker paralel DNS/DoH (default: 12)",
    )
    parser.add_argument(
        "--dns-qps",
        type=float,
        default=None,
        help="[Client] Batas QPS awal total DNS (default: 34)",
    )
    parser.add_argument(
        "--dns-max-qps",
        type=float,
        default=None,
        help="[Client] Batas atas AIMD total QPS DNS (default: 56)",
    )
    parser.add_argument(
        "--dns-inflight",
        type=int,
        default=None,
        help="[Client] Ukuran sliding window ARQ dalam paket (default: 48)",
    )
    parser.add_argument(
        "--dns-uplink-chunk",
        type=int,
        default=None,
        help="[Client] Ukuran payload uplink per segmen DNS dalam byte (default: 72)",
    )
    parser.add_argument(
        "--dns-rto",
        type=float,
        default=None,
        help="[Client] Batas dasar Retransmission Timeout DNS dalam detik (default: 0.75)",
    )
    parser.add_argument(
        "--edns-size",
        type=int,
        choices=[512, 1232],
        default=None,
        help="[Client] Ukuran awal EDNS0 (default: 512)",
    )
    parser.add_argument(
        "--carrier",
        choices=["all", "dns", "doh", "udp", "tcp"],
        default=None,
        help="[Client] Mode carrier aktif: all, dns, doh, udp, atau tcp (default: all)",
    )
    parser.add_argument(
        "--socks-port",
        type=int,
        default=None,
        help="[Client] Port Local SOCKS5 (default: 10808)",
    )
    parser.add_argument(
        "--ssh-forward",
        default=None,
        help="[Client] Aturan forward lokal (default: 127.0.0.1:2222->127.0.0.1:22)",
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=None,
        help="[Client] Interval cetak statistik dalam detik (default: 10)",
    )
    return parser


async def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    cfg = AWPConfig.from_args(args)

    if args.gen_config:
        cfg.save_json(args.gen_config)
        print(f"[{PROTOCOL_BANNER}] Profil konfigurasi ({cfg.mode}) disimpan ke: {args.gen_config}")
        return

    if cfg.mode == "server":
        await AWPServerNode(cfg).run()
    else:
        await AWPClientNode(cfg).run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n[{PROTOCOL_BANNER}] Dihentikan oleh pengguna.")
