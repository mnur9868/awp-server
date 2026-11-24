#!/usr/bin/env python3
from crypto import SPACodec
from doh import DoHClientPool
from quic_udp import QuicCamouflage
from slowdns import DnsCodec
from tls import TLSCamouflage
from ws import WebSocketCamouflage


# =====================================================================
# UNIFIED WIRE CAMOUFLAGE FACADE (SPA, TLS 1.3, WS, QUIC v1, DNS & DoH)
# =====================================================================
class CamouflageCodec(
    SPACodec,
    TLSCamouflage,
    WebSocketCamouflage,
    QuicCamouflage,
    DnsCodec,
):
    """Facade terpadu untuk seluruh encoder/decoder kamuflase protokol AWP v4.7."""
    pass


__all__ = [
    "CamouflageCodec",
    "DoHClientPool",
]
