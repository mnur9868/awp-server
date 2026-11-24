#!/usr/bin/env python3
import hashlib
import hmac
import os
import struct
from typing import Optional, Tuple
import zlib

from config import (
    AWP_V3_SALT,
    FLAG_COMPRESSED,
    FLAG_KEY_RATCHET,
    TYPE_FEC_PARITY,
)


# =====================================================================
# SINGLE PACKET AUTHORIZATION (SPA) & MESIN KRIPTOGRAFI AWP v4.6
# =====================================================================
class SPACodec:
    """Encoder/decoder otentikasi Single Packet Authorization (SPA)."""

    @staticmethod
    def build_spa_packet(
        psk: str,
        session_token: bytes,
        carrier_id: int,
        min_pad: int = 16,
        max_pad: int = 64,
    ) -> bytes:
        root_key = hashlib.blake2b(
            psk.encode("utf-8"), salt=AWP_V3_SALT[:16], digest_size=32
        ).digest()
        salt = os.urandom(16)
        if max_pad <= min_pad:
            pad_len = max(0, min_pad)
        else:
            pad_len = (
                int.from_bytes(os.urandom(1), "big") % (max_pad - min_pad + 1)
                + min_pad
            )
        meta = session_token + bytes([carrier_id, pad_len])
        mask = hashlib.blake2b(salt + b"spa-meta", key=root_key, digest_size=10).digest()
        masked_meta = bytes(a ^ b for a, b in zip(meta, mask))
        mac_tag = hashlib.blake2b(salt + masked_meta, key=root_key, digest_size=16).digest()
        padding = os.urandom(pad_len) if pad_len > 0 else b""
        return salt + masked_meta + mac_tag + padding

    @staticmethod
    def verify_spa_packet(psk: str, packet: bytes) -> Optional[Tuple[bytes, int]]:
        if len(packet) < 42 or len(packet) > 512:
            return None
        root_key = hashlib.blake2b(
            psk.encode("utf-8"), salt=AWP_V3_SALT[:16], digest_size=32
        ).digest()
        salt = packet[:16]
        masked_meta = packet[16:26]
        mac_tag = packet[26:42]
        expected_mac = hashlib.blake2b(
            salt + masked_meta, key=root_key, digest_size=16
        ).digest()
        if not hmac.compare_digest(mac_tag, expected_mac):
            return None
        mask = hashlib.blake2b(salt + b"spa-meta", key=root_key, digest_size=10).digest()
        meta = bytes(a ^ b for a, b in zip(masked_meta, mask))
        token, carrier_id, pad_len = meta[:8], meta[8], meta[9]
        if len(packet) != 42 + pad_len:
            return None
        return token, carrier_id

    @staticmethod
    def extract_stateless_session_token(psk: str, datagram: bytes) -> Optional[bytes]:
        if len(datagram) < 48:
            return None
        root_key = hashlib.blake2b(
            psk.encode("utf-8"), salt=AWP_V3_SALT[:16], digest_size=32
        ).digest()
        wire_nonce = datagram[2:14]
        obf_token = datagram[14:22]
        tmask = hashlib.blake2b(wire_nonce, key=root_key, digest_size=8).digest()
        return bytes(a ^ b for a, b in zip(obf_token, tmask))


class AWPv3Crypto:
    """Mesin kriptografi stream cipher & MAC berbasis BLAKE2b untuk AWP v4.6."""

    def __init__(
        self,
        psk: str,
        session_token: bytes,
        carrier_id: int,
        is_server: bool,
        ordered: bool = True,
        ratchet_interval: int = 500,
    ):
        self.root_key = hashlib.blake2b(
            psk.encode("utf-8"), salt=AWP_V3_SALT[:16], digest_size=32
        ).digest()
        self.session_token = session_token
        self.carrier_id = carrier_id
        self.ordered = ordered

        tag = bytes([carrier_id])
        tx_ctx = (b"v3-s2c-" if is_server else b"v3-c2s-") + tag
        rx_ctx = (b"v3-c2s-" if is_server else b"v3-s2c-") + tag

        self.tx_key = hashlib.blake2b(tx_ctx, key=self.root_key, digest_size=32).digest()
        self.rx_key = hashlib.blake2b(rx_ctx, key=self.root_key, digest_size=32).digest()

        self.tx_seq = 0
        self.ratchet_interval = ratchet_interval
        self.tx_chain = hashlib.blake2b(session_token + tx_ctx, digest_size=12).digest()
        self.rx_chain = hashlib.blake2b(session_token + rx_ctx, digest_size=12).digest()

    def _keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        out = bytearray()
        blk = 0
        while len(out) < length:
            h = hashlib.blake2b(
                nonce + struct.pack("!I", blk), key=key, digest_size=64
            ).digest()
            out.extend(h)
            blk += 1
        return bytes(out[:length])

    def encode_frame(
        self,
        frame_type: int,
        stream_id: int,
        payload: bytes = b"",
        flags: int = 0,
        min_pad: int = 8,
        max_pad: int = 64,
        seq_override: Optional[int] = None,
    ) -> Tuple[bytes, int, bytes]:
        if seq_override is not None:
            seq_num = seq_override
        else:
            self.tx_seq += 1
            seq_num = self.tx_seq

        if self.ordered and (seq_num % self.ratchet_interval == 0):
            flags |= FLAG_KEY_RATCHET

        body_payload = payload
        if len(payload) > 96 and frame_type != TYPE_FEC_PARITY:
            comp = zlib.compress(payload, level=4)
            if len(comp) < len(payload):
                body_payload = comp
                flags |= FLAG_COMPRESSED

        if max_pad <= min_pad:
            pad_len = max(0, min_pad)
        else:
            pad_len = (
                int.from_bytes(os.urandom(2), "big") % (max_pad - min_pad + 1)
                + min_pad
            )
        padding = os.urandom(pad_len) if pad_len > 0 else b""

        inner_header = struct.pack("!BBHIH", flags, frame_type, stream_id, seq_num, pad_len)
        plaintext = inner_header + body_payload + padding

        if self.ordered:
            raw_nonce = os.urandom(4) + struct.pack("!Q", seq_num)
            nmask = hashlib.blake2b(self.tx_chain, key=self.tx_key, digest_size=12).digest()
            wire_nonce = bytes(a ^ b for a, b in zip(raw_nonce, nmask))
            session_tag = b""
        else:
            raw_nonce = os.urandom(12)
            wire_nonce = raw_nonce
            tmask = hashlib.blake2b(wire_nonce, key=self.root_key, digest_size=8).digest()
            session_tag = bytes(a ^ b for a, b in zip(self.session_token, tmask))

        ks = self._keystream(self.tx_key, raw_nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, ks))

        auth_input = wire_nonce + session_tag + ciphertext
        mac_tag = hashlib.blake2b(auth_input, key=self.tx_key, digest_size=16).digest()

        total_body = len(session_tag) + len(ciphertext) + len(mac_tag)
        lmask = hashlib.blake2b(wire_nonce, key=self.tx_key, digest_size=2).digest()
        obf_len = bytes(a ^ b for a, b in zip(struct.pack("!H", total_body), lmask))

        wire_packet = obf_len + wire_nonce + session_tag + ciphertext + mac_tag

        if self.ordered:
            self.tx_chain = hashlib.blake2b(wire_packet, digest_size=12).digest()
            if flags & FLAG_KEY_RATCHET:
                self.tx_key = hashlib.blake2b(
                    b"v3-ratchet", key=self.tx_key, digest_size=32
                ).digest()

        return wire_packet, seq_num, (inner_header + body_payload)

    def decode_frame(self, wire_packet: bytes) -> dict:
        min_size = 2 + 12 + (0 if self.ordered else 8) + 10 + 16
        if len(wire_packet) < min_size:
            raise ValueError("Paket terlalu pendek untuk AWP v4.6")

        obf_len = wire_packet[:2]
        wire_nonce = wire_packet[2:14]

        lmask = hashlib.blake2b(wire_nonce, key=self.rx_key, digest_size=2).digest()
        expected_body = struct.unpack(
            "!H", bytes(a ^ b for a, b in zip(obf_len, lmask))
        )[0]
        if len(wire_packet) != 14 + expected_body:
            raise ValueError("Panjang wire packet tidak sesuai")

        offset = 14
        session_tag = b""
        if not self.ordered:
            session_tag = wire_packet[14:22]
            offset = 22

        ciphertext = wire_packet[offset:-16]
        mac_tag = wire_packet[-16:]

        auth_input = wire_nonce + session_tag + ciphertext
        expected_mac = hashlib.blake2b(
            auth_input, key=self.rx_key, digest_size=16
        ).digest()
        if not hmac.compare_digest(mac_tag, expected_mac):
            raise ValueError("MAC tag AWP tidak valid")

        if self.ordered:
            nmask = hashlib.blake2b(self.rx_chain, key=self.rx_key, digest_size=12).digest()
            raw_nonce = bytes(a ^ b for a, b in zip(wire_nonce, nmask))
        else:
            raw_nonce = wire_nonce

        ks = self._keystream(self.rx_key, raw_nonce, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, ks))

        flags, frame_type, stream_id, seq_num, pad_len = struct.unpack(
            "!BBHIH", plaintext[:10]
        )
        body = plaintext[10:]
        if pad_len > len(body):
            raise ValueError("Pad length tidak valid")

        raw_payload = body[: len(body) - pad_len]
        if flags & FLAG_COMPRESSED:
            raw_payload = zlib.decompress(raw_payload)

        if self.ordered:
            self.rx_chain = hashlib.blake2b(wire_packet, digest_size=12).digest()
            if flags & FLAG_KEY_RATCHET:
                self.rx_key = hashlib.blake2b(
                    b"v3-ratchet", key=self.rx_key, digest_size=32
                ).digest()

        return {
            "flags": flags,
            "type": frame_type,
            "stream_id": stream_id,
            "seq": seq_num,
            "payload": raw_payload,
            "clean_frame": plaintext[: 10 + len(body) - pad_len],
        }
