"""
fuzzer.py
====================
Dedicated fuzzer for QGC — Strategy A.
Searches for vulnerabilities in the QGC MAVLink parser by sending
systematically mutated packets.

Approcci implementati:
  1. SMART fuzzing    — mutates specific fields with boundary values
  2. DUMB fuzzing     — completely random payload
  3. TARGETED fuzzing — high-frequency messages with extreme values
  4. LENGTH fuzzing   — gioca con le lunghezze dei payload

NON richiede Boofuzz — implementazione custom leggera.
(Boofuzz opzionale per fuzzing avanzato con crash detection)

Uso:
    python fuzzer.py --mode smart   --count 2000
    python fuzzer.py --mode dumb    --count 5000
    python fuzzer.py --mode target  --msgid 253  (STATUSTEXT)
    python fuzzer.py --mode length
    python fuzzer.py --mode all     --count 1000

Requirements:
    pip install pymavlink
"""

import socket
import struct
import time
import random
import argparse
import os
import math
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════

TARGET = {
    "ip":   "172.25.0.1",   # IP Windows QGC
    "port": 18570,
}

# Drone compromesso che fa da mittente
ATTACKER = {
    "sysid":  1,
    "compid": 1,
}

# ═══════════════════════════════════════════════════════════════

MAV_V2_STX = 0xFD

CRC_EXTRA = {
    0:   50,   # HEARTBEAT
    1:   124,  # SYS_STATUS
    30:  39,   # ATTITUDE
    31:  246,  # ATTITUDE_QUATERNION
    32:  185,  # LOCAL_POSITION_NED
    33:  104,  # GLOBAL_POSITION_INT
    36:  222,  # SERVO_OUTPUT_RAW
    74:  20,   # VFR_HUD
    76:  152,  # COMMAND_LONG
    77:  143,  # COMMAND_ACK
    83:  22,   # ATTITUDE_TARGET
    85:  140,  # POSITION_TARGET_LOCAL_NED
    87:  150,  # POSITION_TARGET_GLOBAL_INT
    147: 154,  # BATTERY_STATUS
    253: 83,   # STATUSTEXT
    242: 104,  # HOME_POSITION
}

# Messaggi ad alta frequenza nel traffico reale — target principali
HIGH_FREQ_MSGIDS = [33, 32, 30, 31, 85, 36, 83]

# All interesting msgids
ALL_MSGIDS = list(CRC_EXTRA.keys())


def compute_crc(data: bytes, seed: int) -> int:
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    tmp = seed ^ (crc & 0xFF)
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def build_raw_packet(sysid: int, compid: int, msgid: int,
                     payload: bytes, seq: int,
                     crc_extra: int = None,
                     corrupt_crc: bool = False) -> bytes:
    """
    Costruisce pacchetto MAVLink v2.
    Se corrupt_crc=True, il CRC è sbagliato intenzionalmente
    per testare come QGC gestisce pacchetti corrotti.
    """
    if crc_extra is None:
        crc_extra = CRC_EXTRA.get(msgid, random.randint(0, 255))

    msgid_bytes = msgid.to_bytes(3, 'little')
    header = bytes([
        MAV_V2_STX, len(payload) & 0xFF,
        0x00, 0x00,
        seq & 0xFF, sysid, compid,
    ]) + msgid_bytes

    if corrupt_crc:
        crc_bytes = struct.pack('<H', random.randint(0, 0xFFFF))
    else:
        crc_val   = compute_crc(header[1:] + payload, crc_extra)
        crc_bytes = struct.pack('<H', crc_val)

    return header + payload + crc_bytes


# ── Generatori di payload ─────────────────────────────────────────────────────

class PayloadGenerator:

    @staticmethod
    def zeros(n: int) -> bytes:
        return bytes(n)

    @staticmethod
    def all_ff(n: int) -> bytes:
        return bytes([0xFF] * n)

    @staticmethod
    def all_aa(n: int) -> bytes:
        return bytes([0xAA] * n)

    @staticmethod
    def random_bytes(n: int) -> bytes:
        return bytes(random.randint(0, 255) for _ in range(n))

    @staticmethod
    def nan_floats(n: int) -> bytes:
        """Riempi con valori NaN IEEE 754."""
        nf = n // 4
        rem = n % 4
        return struct.pack(f'<{nf}f', *([float('nan')] * nf)) + bytes(rem)

    @staticmethod
    def inf_floats(n: int) -> bytes:
        """Riempi con +INF."""
        nf = n // 4
        rem = n % 4
        return struct.pack(f'<{nf}f', *([float('inf')] * nf)) + bytes(rem)

    @staticmethod
    def neg_inf_floats(n: int) -> bytes:
        """Riempi con -INF."""
        nf = n // 4
        rem = n % 4
        return struct.pack(f'<{nf}f', *([float('-inf')] * nf)) + bytes(rem)

    @staticmethod
    def max_int32(n: int) -> bytes:
        """Riempi con INT32_MAX."""
        ni = n // 4
        rem = n % 4
        return struct.pack(f'<{ni}i', *([2147483647] * ni)) + bytes(rem)

    @staticmethod
    def min_int32(n: int) -> bytes:
        """Riempi con INT32_MIN."""
        ni = n // 4
        rem = n % 4
        return struct.pack(f'<{ni}i', *([-2147483648] * ni)) + bytes(rem)

    @staticmethod
    def alternating(n: int) -> bytes:
        """0x00 e 0xFF alternati."""
        return bytes([0x00 if i % 2 == 0 else 0xFF for i in range(n)])

    @staticmethod
    def format_string(n: int) -> bytes:
        """Payload tipo format string — utile per STATUSTEXT."""
        fs = b'%s%s%s%n%x%x%x%x' * (n // 8 + 1)
        return fs[:n]

    @staticmethod
    def long_string(n: int) -> bytes:
        """Stringa molto lunga — utile per buffer overflow in STATUSTEXT."""
        return b'A' * n

    @staticmethod
    def sql_injection_like(n: int) -> bytes:
        """Caratteri speciali che a volte causano problemi nei parser."""
        chars = b"'\"\\;\x00\x0a\x0d\x1a"
        return (chars * (n // len(chars) + 1))[:n]

    @staticmethod
    def boundary_values_float(n: int) -> bytes:
        """Mix of boundary float values."""
        values = [
            float('nan'), float('inf'), float('-inf'),
            0.0, -0.0, 1.0, -1.0,
            3.4028235e+38,   # FLT_MAX
            -3.4028235e+38,  # FLT_MIN
            1.175494e-38,    # smallest positive float
        ]
        nf  = n // 4
        rem = n % 4
        selected = [random.choice(values) for _ in range(nf)]
        try:
            return struct.pack(f'<{nf}f', *selected) + bytes(rem)
        except Exception:
            return bytes(n)


# ── Fuzzer modes ──────────────────────────────────────────────────────────────

class Fuzzer:
    def __init__(self, target_ip: str, target_port: int):
        self.sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.target = (target_ip, target_port)
        self.seq    = 0
        self.sent   = 0
        self.errors = 0
        self.log    = []

    def send(self, pkt: bytes, label: str = ""):
        try:
            self.sock.sendto(pkt, self.target)
            self.sent += 1
            self.seq = (self.seq + 1) % 256
        except Exception as e:
            self.errors += 1

    def close(self):
        self.sock.close()

    def smart_fuzz(self, count: int = 2000):
        """
        Smart fuzzing: knows MAVLink structure and systematically
        mutates specific fields with boundary values.
        """
        print(f"\n[1] SMART Fuzzing → {self.target[0]}:{self.target[1]}")
        print(f"    {count} iterations — structured field mutation\n")

        gen = PayloadGenerator()

        # Definisce i "casi interessanti" per ogni msgid target
        cases = {
            0: [  # HEARTBEAT (9 bytes attesi)
                ("zeros",    gen.zeros(9)),
                ("all_ff",   gen.all_ff(9)),
                # custom_mode = MAX_UINT32
                ("max_cm",   struct.pack('<IBBBBB', 0xFFFFFFFF, 2, 12, 0xFF, 6, 3)),
                # system_status fuori range
                ("bad_stat", struct.pack('<IBBBBB', 0, 2, 12, 0x80, 0xFF, 3)),
                # type fuori range
                ("bad_type", struct.pack('<IBBBBB', 0, 0xFF, 12, 0x80, 4, 3)),
            ],
            253: [  # STATUSTEXT (51 bytes)
                # severity fuori range
                ("sev_ff",   bytes([0xFF]) + b'A' * 50),
                # testo con null bytes
                ("null_mid", bytes([6])   + b'OK\x00' + b'A' * 47),
                # format string
                ("fmt_str",  bytes([4])   + gen.format_string(50)),
                # buffer overflow tentativo
                ("overflow", bytes([4])   + b'A' * 50),
                # tutto zero
                ("all_zero", bytes([0])   + bytes(50)),
                # testo con caratteri speciali
                ("special",  bytes([4])   + b'%n%s%x\x00' + b'B' * 43),
            ],
            33: [  # GLOBAL_POSITION_INT (28 bytes)
                # lat/lon = MAX_INT32
                ("max_pos",  struct.pack('<IiiiihhhH',
                    0, 2147483647, 2147483647, 2147483647,
                    2147483647, 32767, 32767, 32767, 65535)),
                # lat/lon = MIN_INT32
                ("min_pos",  struct.pack('<IiiiihhhH',
                    0, -2147483648, -2147483648, -2147483648,
                    -2147483648, -32768, -32768, -32768, 0)),
                # tutti zero
                ("zeros",    bytes(28)),
                # altitude = impossibile
                ("bad_alt",  struct.pack('<IiiiihhhH',
                    0, 0, 0, 2147483647, -2147483648,
                    0, 0, 0, 0)),
            ],
            30: [  # ATTITUDE (28 bytes)
                # NaN in roll/pitch/yaw
                ("nan_rpy",  struct.pack('<I', 0) + gen.nan_floats(24)),
                # INF
                ("inf_rpy",  struct.pack('<I', 0) + gen.inf_floats(24)),
                # valori estremi
                ("extreme",  struct.pack('<Iffffff',
                    0xFFFFFFFF,
                    float('nan'), float('inf'), float('-inf'),
                    1e38, -1e38, 0.0)),
            ],
            76: [  # COMMAND_LONG (33 bytes)
                # command = 65535 (fuori range)
                ("bad_cmd",  struct.pack('<fffffffBBHB',
                    0,0,0,0,0,0,0, 1, 1, 65535, 0)),
                # tutti i param a NaN
                ("nan_params", struct.pack('<fffffffBBHB',
                    float('nan'), float('nan'), float('nan'),
                    float('nan'), float('nan'), float('nan'),
                    float('nan'), 1, 1, 400, 0)),
                # target_system = 0 (broadcast)
                ("broadcast", struct.pack('<fffffffBBHB',
                    1,0,0,0,0,0,0, 0, 0, 400, 0)),
            ],
        }

        for msgid, msg_cases in cases.items():
            for case_name, payload in msg_cases:
                pkt = build_raw_packet(
                    ATTACKER["sysid"], ATTACKER["compid"],
                    msgid, payload, self.seq,
                )
                self.send(pkt, f"smart/{msgid}/{case_name}")
                print(f"    msgid={msgid:4d} case={case_name:<12} "
                      f"len={len(payload):3d} seq={self.seq-1}")
                time.sleep(0.02)

        # Riempi il resto con varianti random
        remaining = count - self.sent
        if remaining > 0:
            print(f"\n    Invio {remaining} varianti random aggiuntive...")
            for _ in range(remaining):
                msgid = random.choice(list(cases.keys()))
                n     = random.choice([0, 1, 9, 28, 50, 51, 128, 255])
                gen_func = random.choice([
                    gen.zeros, gen.all_ff, gen.nan_floats,
                    gen.inf_floats, gen.random_bytes, gen.boundary_values_float,
                ])
                payload = gen_func(n) if n > 0 else b''
                pkt = build_raw_packet(
                    ATTACKER["sysid"], ATTACKER["compid"],
                    msgid, payload, self.seq,
                )
                self.send(pkt)
                time.sleep(0.005)

        print(f"\n    [+] Smart fuzzing: {self.sent} pacchetti inviati")

    def dumb_fuzz(self, count: int = 5000):
        """
        Dumb fuzzing: payload completamente casuale su msgid random.
        Veloce e copre casi che lo smart non copre.
        """
        print(f"\n[2] DUMB Fuzzing → {self.target[0]}:{self.target[1]}")
        print(f"    {count} iterations — completely random payload\n")

        # Range esteso di msgid inclusi quelli unknown
        msgid_range = list(range(0, 256)) + [436, 12901, 12904]

        for i in range(count):
            msgid   = random.choice(msgid_range)
            length  = random.randint(0, 255)
            payload = bytes(random.randint(0, 255) for _ in range(length))

            # Sometimes use correct CRC, sometimes wrong
            corrupt = random.random() < 0.1
            pkt = build_raw_packet(
                ATTACKER["sysid"], ATTACKER["compid"],
                msgid, payload, self.seq,
                corrupt_crc=corrupt,
            )
            self.send(pkt)

            if i % 500 == 0:
                elapsed = time.time()
                print(f"    [{i:5d}/{count}] msgid={msgid:5d} "
                      f"len={length:3d} corrupt_crc={corrupt}")

            time.sleep(0.002)

        print(f"\n    [+] Dumb fuzzing: {self.sent} pacchetti inviati")

    def targeted_fuzz(self, msgid: int, count: int = 1000):
        """
        Targeted fuzzing: focused on a single msgid.
        Tests systematically all lengths and all patterns
        for that specific message type.
        """
        print(f"\n[3] TARGETED Fuzzing — msgid={msgid} → {self.target}")
        print(f"    {count} iterazioni\n")

        gen      = PayloadGenerator()
        gen_list = [
            gen.zeros, gen.all_ff, gen.all_aa,
            gen.nan_floats, gen.inf_floats, gen.neg_inf_floats,
            gen.max_int32, gen.min_int32,
            gen.alternating, gen.random_bytes,
            gen.format_string, gen.long_string,
            gen.boundary_values_float,
        ]

        # Boundary lengths
        lengths = [0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17,
                   31, 32, 33, 50, 51, 63, 64, 65,
                   127, 128, 129, 254, 255]

        iteration = 0
        while iteration < count:
            for gen_func in gen_list:
                for length in lengths:
                    if iteration >= count:
                        break
                    payload = gen_func(length) if length > 0 else b''
                    pkt = build_raw_packet(
                        ATTACKER["sysid"], ATTACKER["compid"],
                        msgid, payload, self.seq,
                    )
                    self.send(pkt)
                    iteration += 1

                    if iteration % 100 == 0:
                        print(f"    [{iteration:5d}/{count}] "
                              f"gen={gen_func.__name__:<25} len={length:3d}")

                    time.sleep(0.003)

        print(f"\n    [+] Targeted fuzzing: {self.sent} pacchetti")

    def length_fuzz(self):
        """
        Length fuzzing: per ogni msgid, testa tutte le lunghezze
        da 0 a 255 con payload costante.
        Obiettivo: off-by-one, buffer overflow da length mismatch.
        """
        print(f"\n[4] LENGTH Fuzzing → all msgids, all lengths")

        gen = PayloadGenerator()

        for msgid in ALL_MSGIDS:
            print(f"\n    msgid={msgid} ({msgid}):")
            for length in range(0, 256, 8):  # step 8 per velocità
                payload = gen.random_bytes(length)
                pkt = build_raw_packet(
                    ATTACKER["sysid"], ATTACKER["compid"],
                    msgid, payload, self.seq,
                )
                self.send(pkt)
                time.sleep(0.002)
            print(f"      {256//8} lengths tested")

        print(f"\n    [+] Length fuzzing: {self.sent} pacchetti")


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="fuzzer.py — Strategy A: fuzzing del parser QGC"
    )
    parser.add_argument("--mode",  required=True,
                        choices=["smart", "dumb", "target", "length", "all"],
                        help="Modalità fuzzing")
    parser.add_argument("--count", type=int, default=None,
                        help="Numero iterazioni")
    parser.add_argument("--msgid", type=int, default=253,
                        help="For mode=target: msgid to fuzz (default: 253 STATUSTEXT)")
    parser.add_argument("--target-ip",   default=TARGET["ip"])
    parser.add_argument("--target-port", type=int, default=TARGET["port"])
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  fuzzer.py — MAVLink Fuzzer (Strategy A)")
    print(f"  Target : {args.target_ip}:{args.target_port}")
    print(f"  Sender : sysid={ATTACKER['sysid']} compid={ATTACKER['compid']}")
    print(f"  Mode    : {args.mode}")
    print(f"  Time   : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n  IMPORTANT: Monitor QGC on Windows during fuzzing!")
    print(f"  Se QGC crasha, annota quale pacchetto era l'ultimo inviato.\n")

    fuzzer = Fuzzer(args.target_ip, args.target_port)
    start  = time.time()

    try:
        if args.mode == "smart":
            fuzzer.smart_fuzz(count=args.count or 2000)

        elif args.mode == "dumb":
            fuzzer.dumb_fuzz(count=args.count or 5000)

        elif args.mode == "target":
            fuzzer.targeted_fuzz(
                msgid=args.msgid,
                count=args.count or 1000,
            )

        elif args.mode == "length":
            fuzzer.length_fuzz()

        elif args.mode == "all":
            c = args.count or 500
            fuzzer.smart_fuzz(count=c)
            time.sleep(1)
            fuzzer.targeted_fuzz(msgid=253, count=c)
            time.sleep(1)
            fuzzer.targeted_fuzz(msgid=33,  count=c)
            time.sleep(1)
            fuzzer.dumb_fuzz(count=c * 2)

    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user.")
    finally:
        elapsed = time.time() - start
        fuzzer.close()
        print(f"\n{'='*60}")
        print(f"  Fuzzing summary:")
        print(f"  Pacchetti inviati : {fuzzer.sent}")
        print(f"  Errori            : {fuzzer.errors}")
        print(f"  Durata            : {elapsed:.1f}s")
        print(f"  Velocità media    : {fuzzer.sent/elapsed:.0f} pkt/s")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()