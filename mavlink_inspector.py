"""
MAVLink PCAP Inspector — Objective Wireshark-like Analysis
=========================================================
Displays captured MAVLink traffic in a readable and neutral way,
without making inferences or vulnerability judgments.

Output sections:
  - General traffic statistics
  - Message type distribution
  - Complete packet examples per type (header + decoded payload)
  - System map and observed flows
  - Selective dump of specific packets

Requirements:
    pip install scapy colorama tabulate

Uso:
    # Full analysis with examples
    python mavlink_inspector.py --pcap file.pcap

    # Show N examples per message type
    python mavlink_inspector.py --pcap file.pcap --examples 3

    # Filter by msgid (e.g. COMMAND_LONG=76)
    python mavlink_inspector.py --pcap file.pcap --msgid 76

    # Filter by specific sysid
    python mavlink_inspector.py --pcap file.pcap --sysid 1

    # Save text report
    python mavlink_inspector.py --pcap file.pcap --out report.txt

    # Limit to first N packets (useful for large files)
    python mavlink_inspector.py --pcap file.pcap --limit 10000
"""

import argparse
import sys
import os
import struct
import collections
import json
from datetime import datetime

try:
    from scapy.all import rdpcap, UDP, TCP, Raw, IP
except ImportError:
    print("[!] Installa scapy: pip install scapy")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    print("[!] Installa colorama: pip install colorama")
    class Fore:
        RED=GREEN=YELLOW=CYAN=MAGENTA=WHITE=BLUE=""
    class Style:
        BRIGHT=RESET_ALL=""
    HAS_COLOR = False

try:
    from tabulate import tabulate
except ImportError:
    print("[!] Installa tabulate: pip install tabulate")
    def tabulate(data, headers=[], tablefmt=""):
        out = "  ".join(str(h) for h in headers) + "\n"
        for row in data:
            out += "  ".join(str(x) for x in row) + "\n"
        return out


# ─── MAVLink reference dictionaries ────────────────────────────────────────

MSG_NAMES = {
    0:   "HEARTBEAT",
    1:   "SYS_STATUS",
    2:   "SYSTEM_TIME",
    4:   "PING",
    5:   "CHANGE_OPERATOR_CONTROL",
    6:   "CHANGE_OPERATOR_CONTROL_ACK",
    11:  "SET_MODE",
    20:  "PARAM_REQUEST_READ",
    21:  "PARAM_REQUEST_LIST",
    22:  "PARAM_VALUE",
    23:  "PARAM_SET",
    24:  "GPS_RAW_INT",
    25:  "GPS_STATUS",
    26:  "SCALED_IMU",
    27:  "RAW_IMU",
    29:  "SCALED_PRESSURE",
    30:  "ATTITUDE",
    31:  "ATTITUDE_QUATERNION",
    32:  "LOCAL_POSITION_NED",
    33:  "GLOBAL_POSITION_INT",
    34:  "RC_CHANNELS_SCALED",
    35:  "RC_CHANNELS_RAW",
    36:  "SERVO_OUTPUT_RAW",
    37:  "MISSION_REQUEST_PARTIAL_LIST",
    38:  "MISSION_WRITE_PARTIAL_LIST",
    39:  "MISSION_ITEM",
    40:  "MISSION_REQUEST",
    41:  "MISSION_SET_CURRENT",
    42:  "MISSION_CURRENT",
    43:  "MISSION_REQUEST_LIST",
    44:  "MISSION_COUNT",
    45:  "MISSION_CLEAR_ALL",
    46:  "MISSION_ITEM_REACHED",
    47:  "MISSION_ACK",
    48:  "SET_GPS_GLOBAL_ORIGIN",
    49:  "GPS_GLOBAL_ORIGIN",
    50:  "PARAM_MAP_RC",
    51:  "MISSION_REQUEST_INT",
    54:  "SAFETY_SET_ALLOWED_AREA",
    55:  "SAFETY_ALLOWED_AREA",
    61:  "ATTITUDE_QUATERNION_COV",
    62:  "NAV_CONTROLLER_OUTPUT",
    63:  "GLOBAL_POSITION_INT_COV",
    64:  "LOCAL_POSITION_NED_COV",
    65:  "RC_CHANNELS",
    66:  "REQUEST_DATA_STREAM",
    67:  "DATA_STREAM",
    69:  "MANUAL_CONTROL",
    70:  "RC_CHANNELS_OVERRIDE",
    73:  "MISSION_ITEM_INT",
    74:  "VFR_HUD",
    75:  "COMMAND_INT",
    76:  "COMMAND_LONG",
    77:  "COMMAND_ACK",
    81:  "MANUAL_SETPOINT",
    83:  "ATTITUDE_TARGET",
    84:  "SET_ATTITUDE_TARGET",
    85:  "POSITION_TARGET_LOCAL_NED",
    86:  "SET_POSITION_TARGET_LOCAL_NED",
    87:  "POSITION_TARGET_GLOBAL_INT",
    88:  "SET_POSITION_TARGET_GLOBAL_INT",
    89:  "LOCAL_POSITION_NED_SYSTEM_GLOBAL_OFFSET",
    90:  "HIL_STATE",
    91:  "HIL_CONTROLS",
    92:  "HIL_RC_INPUTS_RAW",
    93:  "HIL_ACTUATOR_CONTROLS",
    100: "OPTICAL_FLOW",
    101: "GLOBAL_VISION_POSITION_ESTIMATE",
    102: "VISION_POSITION_ESTIMATE",
    103: "VISION_SPEED_ESTIMATE",
    104: "VICON_POSITION_ESTIMATE",
    105: "HIGHRES_IMU",
    106: "OPTICAL_FLOW_RAD",
    107: "HIL_SENSOR",
    108: "SIM_STATE",
    109: "RADIO_STATUS",
    110: "FILE_TRANSFER_PROTOCOL",
    111: "TIMESYNC",
    112: "CAMERA_TRIGGER",
    113: "HIL_GPS",
    114: "HIL_OPTICAL_FLOW",
    115: "HIL_STATE_QUATERNION",
    116: "SCALED_IMU2",
    117: "LOG_REQUEST_LIST",
    118: "LOG_ENTRY",
    119: "LOG_REQUEST_DATA",
    120: "LOG_DATA",
    121: "LOG_ERASE",
    122: "LOG_REQUEST_END",
    123: "GPS_INJECT_DATA",
    124: "GPS2_RAW",
    125: "POWER_STATUS",
    126: "SERIAL_CONTROL",
    127: "GPS_RTK",
    128: "GPS2_RTK",
    129: "SCALED_IMU3",
    130: "DATA_TRANSMISSION_HANDSHAKE",
    131: "ENCAPSULATED_DATA",
    132: "DISTANCE_SENSOR",
    133: "TERRAIN_REQUEST",
    134: "TERRAIN_DATA",
    135: "TERRAIN_CHECK",
    136: "TERRAIN_REPORT",
    137: "SCALED_PRESSURE2",
    138: "ATT_POS_MOCAP",
    139: "SET_ACTUATOR_CONTROL_TARGET",
    140: "ACTUATOR_CONTROL_TARGET",
    141: "ALTITUDE",
    142: "RESOURCE_REQUEST",
    143: "SCALED_PRESSURE3",
    144: "FOLLOW_TARGET",
    146: "CONTROL_SYSTEM_STATE",
    147: "BATTERY_STATUS",
    148: "AUTOPILOT_VERSION",
    149: "LANDING_TARGET",
    162: "FENCE_STATUS",
    192: "MAG_CAL_REPORT",
    225: "EFI_STATUS",
    230: "ESTIMATOR_STATUS",
    231: "WIND_COV",
    232: "GPS_INPUT",
    233: "GPS_RTCM_DATA",
    234: "HIGH_LATENCY",
    235: "HIGH_LATENCY2",
    241: "VIBRATION",
    242: "HOME_POSITION",
    243: "SET_HOME_POSITION",
    244: "MESSAGE_INTERVAL",
    245: "EXTENDED_SYS_STATE",
    246: "ADSB_VEHICLE",
    247: "COLLISION",
    248: "V2_EXTENSION",
    249: "MEMORY_VECT",
    250: "DEBUG_VECT",
    251: "NAMED_VALUE_FLOAT",
    252: "NAMED_VALUE_INT",
    253: "STATUSTEXT",
    254: "DEBUG",
    256: "SETUP_SIGNING",
    257: "BUTTON_CHANGE",
    258: "PLAY_TUNE",
    259: "CAMERA_INFORMATION",
    260: "CAMERA_SETTINGS",
    261: "STORAGE_INFORMATION",
    262: "CAMERA_CAPTURE_STATUS",
    263: "CAMERA_IMAGE_CAPTURED",
    264: "FLIGHT_INFORMATION",
    265: "MOUNT_ORIENTATION",
    266: "LOGGING_DATA",
    267: "LOGGING_DATA_ACKED",
    268: "LOGGING_ACK",
    269: "VIDEO_STREAM_INFORMATION",
    270: "VIDEO_STREAM_STATUS",
    299: "WIFI_CONFIG_AP",
    300: "PROTOCOL_VERSION",
    310: "UAVCAN_NODE_STATUS",
    311: "UAVCAN_NODE_INFO",
    320: "PARAM_EXT_REQUEST_READ",
    321: "PARAM_EXT_REQUEST_LIST",
    322: "PARAM_EXT_VALUE",
    323: "PARAM_EXT_SET",
    324: "PARAM_EXT_ACK",
    330: "OBSTACLE_DISTANCE",
    331: "ODOMETRY",
    335: "TRAJECTORY_REPRESENTATION_WAYPOINTS",
    336: "TRAJECTORY_REPRESENTATION_BEZIER",
    340: "CELLULAR_STATUS",
    350: "ISORE_TELEMETRY",
    360: "UTM_GLOBAL_POSITION",
    370: "DEBUG_FLOAT_ARRAY",
    373: "ORBIT_EXECUTION_STATUS",
    375: "SMART_BATTERY_INFO",
    380: "GENERATOR_STATUS",
    385: "ACTUATOR_OUTPUT_STATUS",
    390: "TIME_ESTIMATE_TO_TARGET",
    395: "TUNNEL",
    400: "ONBOARD_COMPUTER_STATUS",
    401: "COMPONENT_METADATA",
    410: "PLAY_TUNE_V2",
    411: "SUPPORTED_TUNES",
    9000: "WHEEL_DISTANCE",
    9005: "WINCH_STATUS",
}

MAV_TYPE = {
    0: "GENERIC", 1: "FIXED_WING", 2: "QUADROTOR", 3: "COAXIAL",
    4: "HELICOPTER", 5: "ANTENNA_TRACKER", 6: "GCS", 7: "AIRSHIP",
    8: "FREE_BALLOON", 9: "ROCKET", 10: "GROUND_ROVER", 11: "SURFACE_BOAT",
    12: "SUBMARINE", 13: "HEXAROTOR", 14: "OCTOROTOR", 15: "TRICOPTER",
    16: "FLAPPING_WING", 17: "KITE", 18: "ONBOARD_CONTROLLER",
    19: "VTOL_DUOROTOR", 20: "VTOL_QUADROTOR", 27: "ADSB", 255: "GCS",
}

MAV_AUTOPILOT = {
    0: "GENERIC", 3: "ARDUPILOTMEGA", 8: "INVALID",
    12: "PX4", 255: "INVALID",
}

MAV_STATE = {
    0: "UNINIT", 1: "BOOT", 2: "CALIBRATING", 3: "STANDBY",
    4: "ACTIVE", 5: "CRITICAL", 6: "EMERGENCY", 7: "POWEROFF", 8: "FLIGHT_TERMINATION",
}

MAV_CMD = {
    16: "NAV_WAYPOINT", 17: "NAV_LOITER_UNLIM", 18: "NAV_LOITER_TURNS",
    19: "NAV_LOITER_TIME", 20: "NAV_RETURN_TO_LAUNCH", 21: "NAV_LAND",
    22: "NAV_TAKEOFF", 31: "NAV_LOITER_TO_ALT", 112: "NAV_DELAY",
    176: "DO_SET_MODE", 177: "DO_JUMP", 178: "DO_CHANGE_SPEED",
    179: "DO_SET_HOME", 183: "DO_SET_SERVO", 186: "DO_REPEAT_RELAY",
    192: "DO_SET_ROI", 197: "DO_MOUNT_CONTROL", 203: "DO_INVERTED_FLIGHT",
    206: "DO_PARACHUTE", 211: "DO_MOTOR_TEST", 300: "MISSION_START",
    400: "COMPONENT_ARM_DISARM", 410: "GET_HOME_POSITION",
    500: "START_RX_PAIR", 520: "GET_MESSAGE_INTERVAL",
    521: "SET_MESSAGE_INTERVAL", 600: "REQUEST_PROTOCOL_VERSION",
    666: "OVERRIDE_GOTO", 2000: "IMAGE_START_CAPTURE",
    2001: "IMAGE_STOP_CAPTURE", 2500: "VIDEO_START_CAPTURE",
    2501: "VIDEO_STOP_CAPTURE",
}


# ─── MAVLink raw parser ───────────────────────────────────────────────────────

def parse_mavlink_from_bytes(data: bytes, pkt_index: int = 0,
                              src_ip: str = "", dst_ip: str = "",
                              src_port: int = 0, dst_port: int = 0,
                              transport: str = "UDP",
                              timestamp: float = 0.0) -> list:
    packets = []
    i = 0
    while i < len(data):
        stx = data[i]

        if stx == 0xFE:  # v1
            if i + 6 > len(data):
                break
            length = data[i+1]
            seq    = data[i+2]
            sysid  = data[i+3]
            compid = data[i+4]
            msgid  = data[i+5]
            total  = 6 + length + 2
            if i + total > len(data):
                i += 1
                continue
            payload = data[i+6 : i+6+length]
            crc_raw = struct.unpack_from('<H', data, i+6+length)[0]
            packets.append({
                "pkt_index":  pkt_index,
                "timestamp":  timestamp,
                "src_ip":     src_ip,
                "dst_ip":     dst_ip,
                "src_port":   src_port,
                "dst_port":   dst_port,
                "transport":  transport,
                "version":    1,
                "stx":        f"0x{stx:02X}",
                "length":     length,
                "seq":        seq,
                "sysid":      sysid,
                "compid":     compid,
                "msgid":      msgid,
                "msg_name":   MSG_NAMES.get(msgid, f"UNKNOWN_{msgid}"),
                "payload":    payload,
                "payload_hex": payload.hex(),
                "crc":        f"0x{crc_raw:04X}",
                "signed":     False,
                "inc_flag":   None,
                "signature":  None,
                "raw_hex":    data[i:i+total].hex(),
            })
            i += total

        elif stx == 0xFD:  # v2
            if i + 10 > len(data):
                break
            length   = data[i+1]
            inc_flag = data[i+2]
            cmp_flag = data[i+3]
            seq      = data[i+4]
            sysid    = data[i+5]
            compid   = data[i+6]
            msgid    = int.from_bytes(data[i+7:i+10], 'little')
            signed   = bool(inc_flag & 0x01)
            sig_len  = 13 if signed else 0
            total    = 10 + length + 2 + sig_len
            if i + total > len(data):
                i += 1
                continue
            payload   = data[i+10 : i+10+length]
            crc_raw   = struct.unpack_from('<H', data, i+10+length)[0]
            signature = data[i+10+length+2 : i+total] if signed else b''

            sig_info = None
            if signed and len(signature) == 13:
                link_id   = signature[0]
                ts_bytes  = signature[1:7]
                ts_val    = int.from_bytes(ts_bytes, 'little')
                mac_bytes = signature[7:13]
                sig_info  = {
                    "link_id":   link_id,
                    "timestamp": ts_val,
                    "mac_hex":   mac_bytes.hex(),
                }

            packets.append({
                "pkt_index":  pkt_index,
                "timestamp":  timestamp,
                "src_ip":     src_ip,
                "dst_ip":     dst_ip,
                "src_port":   src_port,
                "dst_port":   dst_port,
                "transport":  transport,
                "version":    2,
                "stx":        f"0x{stx:02X}",
                "length":     length,
                "inc_flag":   f"0x{inc_flag:02X}",
                "cmp_flag":   f"0x{cmp_flag:02X}",
                "seq":        seq,
                "sysid":      sysid,
                "compid":     compid,
                "msgid":      msgid,
                "msg_name":   MSG_NAMES.get(msgid, f"UNKNOWN_{msgid}"),
                "payload":    payload,
                "payload_hex": payload.hex(),
                "crc":        f"0x{crc_raw:04X}",
                "signed":     signed,
                "inc_flag_raw": inc_flag,
                "signature":  sig_info,
                "raw_hex":    data[i:i+total].hex(),
            })
            i += total
        else:
            i += 1

    return packets


# ─── Payload decoder per message type ────────────────────────────────────

def decode_payload(msgid: int, payload: bytes) -> dict:
    """
    Decodes payload for the most common message types.
    Returns a dict with named fields.
    """
    try:
        if msgid == 0 and len(payload) >= 9:  # HEARTBEAT
            cm, mt, ap, bm, ss, mv = struct.unpack_from('<IBBBBB', payload)
            return {
                "custom_mode":   cm,
                "type":          f"{mt} ({MAV_TYPE.get(mt,'?')})",
                "autopilot":     f"{ap} ({MAV_AUTOPILOT.get(ap,'?')})",
                "base_mode":     f"0x{bm:02X}",
                "armed":         bool(bm & 0x80),
                "auto_mode":     bool(bm & 0x04),
                "guided_mode":   bool(bm & 0x08),
                "stabilize":     bool(bm & 0x10),
                "system_status": f"{ss} ({MAV_STATE.get(ss,'?')})",
                "mavlink_version": mv,
            }

        elif msgid == 1 and len(payload) >= 20:  # SYS_STATUS
            (onboard_control_sensors_present,
             onboard_control_sensors_enabled,
             onboard_control_sensors_health,
             load, voltage_battery, current_battery,
             drop_rate_comm, errors_comm) = struct.unpack_from('<IIIHiHHH', payload[:24])
            return {
                "battery_voltage_mV": voltage_battery,
                "battery_current_cA": current_battery,
                "cpu_load_%":         load / 10.0,
                "drop_rate_comm_%":   drop_rate_comm / 100.0,
                "errors_comm":        errors_comm,
            }

        elif msgid == 24 and len(payload) >= 30:  # GPS_RAW_INT
            ts, lat, lon, alt, eph, epv, vel, cog, fix, sats = \
                struct.unpack_from('<QiiiHHHHBB', payload[:30])
            return {
                "fix_type":  fix,
                "lat_deg":   lat / 1e7,
                "lon_deg":   lon / 1e7,
                "alt_mm":    alt,
                "alt_m":     alt / 1000.0,
                "vel_cm_s":  vel,
                "satellites": sats,
                "hdop":      eph / 100.0,
            }

        elif msgid == 30 and len(payload) >= 24:  # ATTITUDE
            ts, roll, pitch, yaw, rollspeed, pitchspeed, yawspeed = \
                struct.unpack_from('<Iffffff', payload[:28])
            import math
            return {
                "roll_deg":   math.degrees(roll),
                "pitch_deg":  math.degrees(pitch),
                "yaw_deg":    math.degrees(yaw),
                "rollspeed_rad_s":  rollspeed,
                "pitchspeed_rad_s": pitchspeed,
                "yawspeed_rad_s":   yawspeed,
            }

        elif msgid == 33 and len(payload) >= 28:  # GLOBAL_POSITION_INT
            ts, lat, lon, alt, rel_alt, vx, vy, vz, hdg = \
                struct.unpack_from('<IiiiihhhH', payload[:28])
            return {
                "lat_deg":    lat / 1e7,
                "lon_deg":    lon / 1e7,
                "alt_m":      alt / 1000.0,
                "rel_alt_m":  rel_alt / 1000.0,
                "vx_cm_s":    vx,
                "vy_cm_s":    vy,
                "vz_cm_s":    vz,
                "heading_cdeg": hdg,
            }

        elif msgid == 74 and len(payload) >= 20:  # VFR_HUD
            airspeed, groundspeed, alt, climb, heading, throttle = \
                struct.unpack_from('<ffhfhH', payload[:20])  # fix: use correct format
            return {
                "airspeed_m_s":    airspeed,
                "groundspeed_m_s": groundspeed,
                "heading_deg":     heading,
                "throttle_%":      throttle,
                "alt_m":           alt,
                "climb_m_s":       climb,
            }

        elif msgid == 76 and len(payload) >= 30:  # COMMAND_LONG
            p1,p2,p3,p4,p5,p6,p7 = struct.unpack_from('<7f', payload, 0)
            ts  = payload[28]
            tc  = payload[29]
            cmd = struct.unpack_from('<H', payload, 30)[0]
            cf  = payload[32] if len(payload) > 32 else 0
            return {
                "target_system":    ts,
                "target_component": tc,
                "command_id":       cmd,
                "command_name":     MAV_CMD.get(cmd, f"CMD_{cmd}"),
                "confirmation":     cf,
                "param1": p1, "param2": p2, "param3": p3, "param4": p4,
                "param5": p5, "param6": p6, "param7": p7,
            }

        elif msgid == 77 and len(payload) >= 3:  # COMMAND_ACK
            cmd, result = struct.unpack_from('<HB', payload)
            result_names = {0:"ACCEPTED",1:"TEMP_REJECTED",2:"DENIED",
                            3:"UNSUPPORTED",4:"FAILED",5:"IN_PROGRESS"}
            return {
                "command_id":   cmd,
                "command_name": MAV_CMD.get(cmd, f"CMD_{cmd}"),
                "result":       f"{result} ({result_names.get(result,'?')})",
            }

        elif msgid == 111 and len(payload) >= 16:  # TIMESYNC
            tc1, ts1 = struct.unpack_from('<qq', payload[:16])
            return {"tc1_ns": tc1, "ts1_ns": ts1}

        elif msgid == 147 and len(payload) >= 9:  # BATTERY_STATUS
            (bid, bfunc, btype, temp,
             voltages) = struct.unpack_from('<BBBhH', payload[:7])
            return {
                "battery_id":       bid,
                "battery_function": bfunc,
                "type":             btype,
                "temperature_cdegC": temp,
            }

        elif msgid == 253 and len(payload) >= 2:  # STATUSTEXT
            severity = payload[0]
            text = payload[1:51].rstrip(b'\x00').decode('utf-8', errors='replace')
            sev_names = {0:"EMERGENCY",1:"ALERT",2:"CRITICAL",3:"ERROR",
                         4:"WARNING",5:"NOTICE",6:"INFO",7:"DEBUG"}
            return {
                "severity": f"{severity} ({sev_names.get(severity,'?')})",
                "text":     text,
            }

        else:
            return {"raw_hex": payload.hex(), "length": len(payload)}

    except Exception as e:
        return {"decode_error": str(e), "raw_hex": payload.hex()}


# ─── Full packet print ────────────────────────────────────────────────

def print_packet_full(pkt: dict, out=None):
    """
    Prints a complete MAVLink packet in readable format.
    If out is provided, also writes to file.
    """
    def w(line=""):
        print(line)
        if out:
            out.write(line + "\n")

    decoded = decode_payload(pkt["msgid"], pkt["payload"])
    ts_str  = f"{pkt['timestamp']:.6f}" if pkt["timestamp"] else "N/A"

    w(f"{Fore.CYAN}┌─ Packet #{pkt['pkt_index']}  "
      f"ts={ts_str}  "
      f"{pkt['transport']} {pkt['src_ip']}:{pkt['src_port']} → "
      f"{pkt['dst_ip']}:{pkt['dst_port']}{Style.RESET_ALL}")

    # MAVLink Header
    w(f"│  {Style.BRIGHT}MAVLink Header:{Style.RESET_ALL}")
    w(f"│    version   : {Fore.YELLOW}v{pkt['version']}{Style.RESET_ALL}")
    w(f"│    STX       : {pkt['stx']}")
    w(f"│    length    : {pkt['length']} bytes")
    w(f"│    seq       : {pkt['seq']}")
    w(f"│    sysid     : {Fore.GREEN}{pkt['sysid']}{Style.RESET_ALL}")
    w(f"│    compid    : {pkt['compid']}")
    w(f"│    msgid     : {pkt['msgid']}  ({Fore.MAGENTA}{pkt['msg_name']}{Style.RESET_ALL})")
    w(f"│    crc       : {pkt['crc']}")

    if pkt["version"] == 2:
        w(f"│    inc_flag  : {pkt['inc_flag']}")
        w(f"│    cmp_flag  : {pkt['cmp_flag']}")
        signed_str = (f"{Fore.RED}YES ← signed{Style.RESET_ALL}"
                      if pkt["signed"] else
                      f"{Fore.YELLOW}NO  ← non signed{Style.RESET_ALL}")
        w(f"│    signed    : {signed_str}")
        if pkt["signed"] and pkt["signature"]:
            s = pkt["signature"]
            w(f"│    signature :")
            w(f"│      link_id  : {s['link_id']}")
            w(f"│      timestamp: {s['timestamp']} (x10µs since 2015-01-01)")
            w(f"│      mac_48   : {s['mac_hex']}")

    # Raw hex payload
    w(f"│  {Style.BRIGHT}Payload ({pkt['length']} bytes):{Style.RESET_ALL}")
    hex_str = pkt["payload_hex"]
    for chunk_start in range(0, len(hex_str), 32):
        chunk = hex_str[chunk_start:chunk_start+32]
        spaced = " ".join(chunk[j:j+2] for j in range(0, len(chunk), 2))
        w(f"│    {spaced}")

    # Decoded payload
    w(f"│  {Style.BRIGHT}Decoded payload:{Style.RESET_ALL}")
    for k, v in decoded.items():
        if isinstance(v, float):
            w(f"│    {k:<28} = {v:.6f}")
        else:
            w(f"│    {k:<28} = {v}")

    w(f"└{'─'*70}")
    w()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MAVLink PCAP Inspector — Objective Wireshark-like analysis"
    )
    parser.add_argument("--pcap",     required=True, help="Path to .pcap file")
    parser.add_argument("--examples", type=int, default=2,
                        help="Number of examples per message type (default: 2)")
    parser.add_argument("--msgid",    type=int, default=None,
                        help="Show only packets with this msgid")
    parser.add_argument("--sysid",    type=int, default=None,
                        help="Filter by sysid")
    parser.add_argument("--limit",    type=int, default=0,
                        help="Analyze only first N packets (0=all)")
    parser.add_argument("--out",      default=None,
                        help="Save output to .txt file")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"[!] File not found: {args.pcap}")
        sys.exit(1)

    out_file = open(args.out, "w", encoding="utf-8") if args.out else None

    def w(line=""):
        print(line)
        if out_file:
            # strip color codes for file output
            import re
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
            out_file.write(clean + "\n")

    w(f"\n{'='*70}")
    w(f"  MAVLink PCAP Inspector")
    w(f"  File    : {args.pcap}")
    w(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"{'='*70}\n")

    # ── Load PCAP ──
    w(f"[*] Loading PCAP...")
    scapy_pkts = rdpcap(args.pcap)
    w(f"    Total packets in file : {len(scapy_pkts)}")

    # ── Extract MAVLink ──
    w(f"[*] Extracting MAVLink packets...")
    all_mav  = []
    port_map = collections.Counter()
    ip_pairs = collections.Counter()

    limit = args.limit if args.limit > 0 else len(scapy_pkts)
    for idx, pkt in enumerate(scapy_pkts[:limit]):
        src_ip = dst_ip = ""
        src_port = dst_port = 0
        transport = ""
        ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

        if pkt.haslayer(UDP) and pkt.haslayer(Raw):
            src_port  = pkt[UDP].sport
            dst_port  = pkt[UDP].dport
            transport = "UDP"
            port_map[dst_port] += 1
            ip_pairs[(src_ip, dst_ip)] += 1
            raw = bytes(pkt[Raw])
            parsed = parse_mavlink_from_bytes(raw, idx, src_ip, dst_ip,
                                               src_port, dst_port, transport, ts)
            all_mav.extend(parsed)

        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            src_port  = pkt[TCP].sport
            dst_port  = pkt[TCP].dport
            transport = "TCP"
            port_map[dst_port] += 1
            ip_pairs[(src_ip, dst_ip)] += 1
            raw = bytes(pkt[Raw])
            parsed = parse_mavlink_from_bytes(raw, idx, src_ip, dst_ip,
                                               src_port, dst_port, transport, ts)
            all_mav.extend(parsed)

    w(f"    MAVLink packets found  : {len(all_mav)}\n")

    if not all_mav:
        w("[!] No MAVLink packets found.")
        w("    Most used UDP ports:")
        for port, cnt in port_map.most_common(10):
            w(f"      {port}: {cnt}")
        sys.exit(1)

    # ── Apply filters ──
    filtered = all_mav
    if args.sysid is not None:
        filtered = [p for p in filtered if p["sysid"] == args.sysid]
        w(f"[*] Filter sysid={args.sysid} → {len(filtered)} packets")
    if args.msgid is not None:
        filtered = [p for p in filtered if p["msgid"] == args.msgid]
        w(f"[*] Filter msgid={args.msgid} → {len(filtered)} packets")

    # ────────────────────────────────────────────────────────────────
    # SECTION 1: General overview
    # ────────────────────────────────────────────────────────────────
    w(f"\n{'─'*70}")
    w(f"  [1] GENERAL OVERVIEW")
    w(f"{'─'*70}")

    v1_pkts = [p for p in all_mav if p["version"] == 1]
    v2_pkts = [p for p in all_mav if p["version"] == 2]
    v2_signed   = [p for p in v2_pkts if p["signed"]]
    v2_unsigned = [p for p in v2_pkts if not p["signed"]]

    w(f"  MAVLink v1 packets  : {len(v1_pkts):>6} packets")
    w(f"  MAVLink v2 packets  : {len(v2_pkts):>6} packets")
    w(f"    of which signed   : {len(v2_signed):>6}")
    w(f"    of which UNSIGNED : {len(v2_unsigned):>6}")

    w(f"\n  Network ports used (top 5 by destination):")
    port_rows = [[p, c] for p,c in port_map.most_common(5)]
    w(tabulate(port_rows, headers=["Dst Port", "Packets"], tablefmt="simple"))

    w(f"\n  Observed IP flows:")
    for (s, d), c in ip_pairs.most_common():
        w(f"    {s} → {d}  :  {c} packets")

    # ────────────────────────────────────────────────────────────────
    # SECTION 2: Message distribution
    # ────────────────────────────────────────────────────────────────
    w(f"\n{'─'*70}")
    w(f"  [2] MESSAGE TYPE DISTRIBUTION")
    w(f"{'─'*70}")

    msg_counter = collections.Counter(p["msgid"] for p in all_mav)
    msg_rows = []
    for msgid, count in msg_counter.most_common():
        name    = MSG_NAMES.get(msgid, f"UNKNOWN_{msgid}")
        pct     = count / len(all_mav) * 100
        msg_rows.append([msgid, name, count, f"{pct:.1f}%"])
    w(tabulate(msg_rows,
               headers=["MsgID", "Name", "Count", "%"],
               tablefmt="simple"))

    # ────────────────────────────────────────────────────────────────
    # SECTION 3: System map
    # ────────────────────────────────────────────────────────────────
    w(f"\n{'─'*70}")
    w(f"  [3] IDENTIFIED SYSTEMS")
    w(f"{'─'*70}")

    systems = collections.defaultdict(lambda: {"count": 0, "msgids": set()})
    for p in all_mav:
        key = (p["sysid"], p["compid"])
        systems[key]["count"] += 1
        systems[key]["msgids"].add(p["msgid"])

    sys_rows = []
    for (sysid, compid), info in sorted(systems.items()):
        msg_names_str = ", ".join(
            MSG_NAMES.get(m, str(m)) for m in sorted(info["msgids"])[:5]
        )
        if len(info["msgids"]) > 5:
            msg_names_str += f" ... +{len(info['msgids'])-5}"
        sys_rows.append([sysid, compid, info["count"], msg_names_str])
    w(tabulate(sys_rows,
               headers=["sysid", "compid", "Packets", "Messages sent (top 5)"],
               tablefmt="simple"))

    # Heartbeat detail
    hb_pkts = [p for p in all_mav if p["msgid"] == 0]
    if hb_pkts:
        w(f"\n  HEARTBEAT detail per system:")
        seen = set()
        for p in hb_pkts:
            key = (p["sysid"], p["compid"])
            if key in seen:
                continue
            seen.add(key)
            d = decode_payload(0, p["payload"])
            w(f"    sysid={p['sysid']} compid={p['compid']} | "
              f"type={d.get('type','?')} | "
              f"autopilot={d.get('autopilot','?')} | "
              f"armed={d.get('armed','?')} | "
              f"status={d.get('system_status','?')}")

    # ────────────────────────────────────────────────────────────────
    # SECTION 4: Sequence number analysis
    # ────────────────────────────────────────────────────────────────
    w(f"\n{'─'*70}")
    w(f"  [4] SEQUENCE NUMBERS PER STREAM")
    w(f"{'─'*70}")

    streams = collections.defaultdict(list)
    for p in all_mav:
        streams[(p["sysid"], p["compid"])].append(p["seq"])

    for (sysid, compid), seqs in sorted(streams.items()):
        gaps = 0
        resets = 0
        for j in range(1, len(seqs)):
            exp = (seqs[j-1] + 1) % 256
            if seqs[j] != exp:
                if seqs[j] < seqs[j-1]:
                    resets += 1
                else:
                    gaps += 1
        w(f"  sysid={sysid} compid={compid}: "
          f"{len(seqs)} packets | "
          f"seq range [{min(seqs)}–{max(seqs)}] | "
          f"gap={gaps} | reset={resets}")

    # ────────────────────────────────────────────────────────────────
    # SECTION 5: Complete examples per message type
    # ────────────────────────────────────────────────────────────────
    w(f"\n{'─'*70}")
    w(f"  [5] COMPLETE PACKET EXAMPLES")
    w(f"  ({args.examples} example(s) per message type)")
    w(f"{'─'*70}\n")

    by_type = collections.defaultdict(list)
    for p in filtered:
        by_type[p["msgid"]].append(p)

    for msgid in sorted(by_type.keys()):
        pkts_of_type = by_type[msgid]
        name = MSG_NAMES.get(msgid, f"UNKNOWN_{msgid}")
        w(f"\n{'━'*70}")
        w(f"  MSG {msgid} — {name}  ({len(pkts_of_type)} total packets)")
        w(f"{'━'*70}")
        for example in pkts_of_type[:args.examples]:
            print_packet_full(example, out_file)

    # ────────────────────────────────────────────────────────────────
    # SECTION 6: COMMAND_LONG detail
    # ────────────────────────────────────────────────────────────────
    cmd_pkts = [p for p in all_mav if p["msgid"] == 76]
    if cmd_pkts:
        w(f"\n{'─'*70}")
        w(f"  [6] ALL INTERCEPTED COMMAND_LONG ({len(cmd_pkts)} totali)")
        w(f"{'─'*70}")
        for p in cmd_pkts:
            d = decode_payload(76, p["payload"])
            w(f"  seq={p['seq']:3d} | sysid={p['sysid']} → target={d.get('target_system','?')} | "
              f"cmd={d.get('command_id','?')} ({d.get('command_name','?')}) | "
              f"confirm={d.get('confirmation','?')} | "
              f"params=[{d.get('param1',0):.1f}, {d.get('param2',0):.1f}, "
              f"{d.get('param3',0):.1f}, {d.get('param7',0):.1f}]")

    # ────────────────────────────────────────────────────────────────
    # SECTION 7: STATUSTEXT
    # ────────────────────────────────────────────────────────────────
    st_pkts = [p for p in all_mav if p["msgid"] == 253]
    if st_pkts:
        w(f"\n{'─'*70}")
        w(f"  [7] STATUSTEXT ({len(st_pkts)} messages)")
        w(f"{'─'*70}")
        for p in st_pkts:
            d = decode_payload(253, p["payload"])
            w(f"  [{d.get('severity','?')}] {d.get('text','')}")

    w(f"\n{'='*70}")
    w(f"  Analysis complete — {len(all_mav)} MAVLink packets examined")
    w(f"{'='*70}\n")

    if out_file:
        out_file.close()
        print(f"\n[+] Report saved to: {args.out}")


if __name__ == "__main__":
    main()