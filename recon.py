"""
Script 1: recon.py
==================
Ricognizione passiva — ascolta il traffico MAVLink e mappa
tutti i nodi presenti (droni + GCS) senza inviare nulla.

Uso:
    python recon.py
    python recon.py --duration 15       # ascolta per 15 secondi
    python recon.py --port 18570        # porta specifica
    python recon.py --host 0.0.0.0      # ascolta su tutte le interfacce

Requisiti:
    pip install pymavlink
"""

import socket
import struct
import time
import argparse
import collections
from datetime import datetime

# ── Nomi messaggi MAVLink più comuni ─────────────────────────────────────────
MSG_NAMES = {
    0: "HEARTBEAT", 1: "SYS_STATUS", 24: "GPS_RAW_INT",
    30: "ATTITUDE", 33: "GLOBAL_POSITION_INT", 74: "VFR_HUD",
    76: "COMMAND_LONG", 77: "COMMAND_ACK", 253: "STATUSTEXT",
    242: "HOME_POSITION", 147: "BATTERY_STATUS",
}

MAV_TYPE = {
    0: "GENERIC", 1: "FIXED_WING", 2: "QUADROTOR",
    6: "GCS", 255: "GCS",
}

MAV_STATE = {
    0: "UNINIT", 1: "BOOT", 2: "CALIBRATING", 3: "STANDBY",
    4: "ACTIVE", 5: "CRITICAL", 6: "EMERGENCY",
    7: "POWEROFF", 8: "FLIGHT_TERMINATION",
}


def parse_mavlink_header(data: bytes):
    """
    Estrae i campi header da un pacchetto MAVLink v1 o v2.
    Ritorna dict con i campi o None se non è MAVLink.
    """
    if len(data) < 8:
        return None

    stx = data[0]

    if stx == 0xFE and len(data) >= 8:  # v1
        length = data[1]
        seq    = data[2]
        sysid  = data[3]
        compid = data[4]
        msgid  = data[5]
        return {
            "version": 1,
            "length":  length,
            "seq":     seq,
            "sysid":   sysid,
            "compid":  compid,
            "msgid":   msgid,
            "signed":  False,
            "payload": data[6:6+length] if len(data) >= 6+length else b'',
        }

    elif stx == 0xFD and len(data) >= 10:  # v2
        length   = data[1]
        inc_flag = data[2]
        seq      = data[4]
        sysid    = data[5]
        compid   = data[6]
        msgid    = int.from_bytes(data[7:10], 'little')
        signed   = bool(inc_flag & 0x01)
        return {
            "version": 2,
            "length":  length,
            "seq":     seq,
            "sysid":   sysid,
            "compid":  compid,
            "msgid":   msgid,
            "signed":  signed,
            "payload": data[10:10+length] if len(data) >= 10+length else b'',
        }

    return None


def decode_heartbeat(payload: bytes) -> dict:
    """Decodifica payload HEARTBEAT."""
    if len(payload) < 9:
        return {}
    try:
        cm = struct.unpack_from('<I', payload, 0)[0]
        mt, ap, bm, ss, mv = payload[4], payload[5], payload[6], payload[7], payload[8]
        return {
            "mav_type":      f"{mt} ({MAV_TYPE.get(mt, '?')})",
            "autopilot":     ap,
            "base_mode":     f"0x{bm:02X}",
            "armed":         bool(bm & 0x80),
            "system_status": f"{ss} ({MAV_STATE.get(ss, '?')})",
            "custom_mode":   cm,
        }
    except Exception:
        return {}


def main():
    parser = argparse.ArgumentParser(description="MAVLink Recon — ricognizione passiva")
    parser.add_argument("--host",     default="0.0.0.0", help="Interfaccia ascolto")
    parser.add_argument("--port",     type=int, default=18570, help="Porta UDP")
    parser.add_argument("--duration", type=int, default=10,
                        help="Durata ascolto in secondi (default: 10)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.settimeout(1.0)

    print(f"\n{'='*60}")
    print(f"  MAVLink Recon — Ricognizione Passiva")
    print(f"  Ascolto su {args.host}:{args.port} per {args.duration}s")
    print(f"{'='*60}\n")

    # Strutture dati per raccogliere info
    nodes   = {}          # (sysid, compid) → info
    traffic = collections.Counter()   # (src_ip, sysid) → count
    msg_count = collections.Counter() # msgid → count
    seq_tracker = {}      # (sysid, compid) → ultimo seq

    start = time.time()
    total_pkts = 0

    print(f"[*] Ascolto in corso", end="", flush=True)

    while time.time() - start < args.duration:
        try:
            data, addr = sock.recvfrom(4096)
            src_ip   = addr[0]
            src_port = addr[1]

            # Prova a parsare come MAVLink
            pkt = parse_mavlink_header(data)
            if pkt is None:
                continue

            total_pkts += 1
            sysid  = pkt["sysid"]
            compid = pkt["compid"]
            msgid  = pkt["msgid"]
            key    = (sysid, compid)

            # Aggiorna info nodo
            if key not in nodes:
                nodes[key] = {
                    "sysid":    sysid,
                    "compid":   compid,
                    "ip":       src_ip,
                    "port":     src_port,
                    "version":  pkt["version"],
                    "signed":   pkt["signed"],
                    "first_seen": datetime.now().strftime("%H:%M:%S"),
                    "msgids":   set(),
                    "hb_info":  None,
                    "last_seq": pkt["seq"],
                    "seq_gaps": 0,
                }
                print(f"\n  [+] Nuovo nodo: sysid={sysid} compid={compid} "
                      f"IP={src_ip}:{src_port}")

            node = nodes[key]
            node["ip"]      = src_ip
            node["port"]    = src_port
            node["signed"]  = node["signed"] or pkt["signed"]
            node["msgids"].add(msgid)

            # Controlla sequence gaps
            if key in seq_tracker:
                expected = (seq_tracker[key] + 1) % 256
                if pkt["seq"] != expected:
                    node["seq_gaps"] += 1
            seq_tracker[key] = pkt["seq"]

            # Decodifica HEARTBEAT
            if msgid == 0 and pkt["payload"]:
                hb = decode_heartbeat(pkt["payload"])
                if hb:
                    node["hb_info"] = hb

            msg_count[msgid] += 1
            traffic[(src_ip, sysid)] += 1

        except socket.timeout:
            print(".", end="", flush=True)
            continue
        except Exception as e:
            continue

    sock.close()
    print(f"\n\n[*] Ascolto terminato. {total_pkts} pacchetti MAVLink ricevuti.\n")

    # ── Report nodi ──────────────────────────────────────────────────────────
    print(f"{'─'*60}")
    print(f"  NODI IDENTIFICATI ({len(nodes)} totali)")
    print(f"{'─'*60}")

    for (sysid, compid), node in sorted(nodes.items()):
        print(f"\n  ┌─ sysid={sysid} compid={compid}")
        print(f"  │  IP            : {node['ip']}:{node['port']}")
        print(f"  │  MAVLink ver   : v{node['version']}")
        print(f"  │  Firmato       : {'SI ← attenzione' if node['signed'] else 'NO ← vulnerabile'}")
        print(f"  │  Prima vista   : {node['first_seen']}")
        print(f"  │  Seq gaps      : {node['seq_gaps']}")

        if node["hb_info"]:
            hb = node["hb_info"]
            print(f"  │  Tipo          : {hb.get('mav_type', '?')}")
            print(f"  │  Armed         : {hb.get('armed', '?')}")
            print(f"  │  Stato         : {hb.get('system_status', '?')}")
            print(f"  │  Base mode     : {hb.get('base_mode', '?')}")

        msg_names = [MSG_NAMES.get(m, f"MSG_{m}") for m in sorted(node["msgids"])[:6]]
        print(f"  │  Messaggi      : {', '.join(msg_names)}"
              f"{'...' if len(node['msgids']) > 6 else ''}")
        print(f"  └─ Totale pacchetti: "
              f"{sum(v for (ip,s),v in traffic.items() if s == sysid)}")

    # ── Riepilogo per attacco ─────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  RIEPILOGO PER ATTACCO")
    print(f"{'─'*60}")

    drones = [(s, c, n) for (s,c), n in nodes.items() if s != 255 and s < 250]
    gcss   = [(s, c, n) for (s,c), n in nodes.items() if s == 255 or s >= 250]

    print(f"\n  Droni trovati: {len(drones)}")
    for s, c, n in sorted(drones):
        print(f"    → sysid={s} compid={c} @ {n['ip']}:{n['port']}")

    print(f"\n  GCS trovate: {len(gcss)}")
    for s, c, n in sorted(gcss):
        print(f"    → sysid={s} compid={c} @ {n['ip']}:{n['port']}")

    print(f"\n  Porta attiva: UDP {args.port}")
    print(f"  Firma attiva: {'SI — serve Strategy B avanzata' if any(n['signed'] for n in nodes.values()) else 'NO — injection diretta possibile'}")

    # ── Genera config per gli altri script ────────────────────────────────────
    if nodes:
        print(f"\n{'─'*60}")
        print(f"  CONFIG DA USARE NEGLI ALTRI SCRIPT")
        print(f"{'─'*60}")
        print(f"\n  Copia questi valori in inject_qgc.py e inject_drones.py:\n")

        for s, c, n in sorted(drones):
            print(f"  DRONE_{s} = {{'sysid': {s}, 'compid': {c}, "
                  f"'ip': '{n['ip']}', 'port': {n['port']}}}")

        for s, c, n in sorted(gcss):
            print(f"  GCS       = {{'sysid': {s}, 'compid': {c}, "
                  f"'ip': '{n['ip']}', 'port': {n['port']}}}")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
