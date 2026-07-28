#!/bin/bash
# Deploy HiveRelay to VPS servers
# Usage: ./scripts/deploy-vps.sh [utah|utah-us|singapore|all]
#
# Creates a systemd service with auto-restart, memory limits, and proper region tagging.
# Kills any old processes from /opt/hiverelay or nohup before enabling the systemd service.

set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/hiverelay_fleet}"
API_KEY="${HIVERELAY_API_KEY:?Set HIVERELAY_API_KEY environment variable}"

# Server IPs
UTAH_IP="${UTAH_IP:-144.172.101.215}"
UTAH_US_IP="${UTAH_US_IP:-144.172.91.26}"
SINGAPORE_IP="${SINGAPORE_IP:-104.194.153.179}"
SINGAPORE2_IP="${SINGAPORE2_IP:-104.194.152.121}"
BERN_IP="${BERN_IP:-45.59.123.112}"

# Per-relay API keys (override the env-var fallback so each relay gets its own
# strong key). Set via env var to rotate without editing this script.
UTAH_API_KEY="${UTAH_API_KEY:-}"
UTAH_US_API_KEY="${UTAH_US_API_KEY:-}"
SINGAPORE_API_KEY="${SINGAPORE_API_KEY:-}"
SINGAPORE2_API_KEY="${SINGAPORE2_API_KEY:-}"
BERN_API_KEY="${BERN_API_KEY:-}"

# Operator — DELIBERATELY UNSET. This is an anonymity network.
#
# The capability doc is unauthenticated: anything set here is served to anyone
# who asks. Declaring an operator publishes a linkage set naming every relay
# one party runs — precisely the correlation the Tor path, blind cells and
# split transport exist to prevent. A named value ("hive-foundation-utah") is
# worse still: it links the fleet to a real-world entity that can be
# subpoenaed, pressured or blocked wholesale.
#
# Leaving it unset is not a gap. quorum-selector treats undeclared as
# `__undeclared__` and never counts it toward independence, so this fleet
# forfeits diversity credit instead of leaking identity to claim it. For a
# single-owner fleet that credit would have been false anyway.
#
# If a future deployment must be countable, set an OPAQUE random token shared
# across that operator's relays — never a name. See capability-doc.js.
HIVE_OPERATOR="${HIVE_OPERATOR:-}"
UTAH_OPERATOR="${UTAH_OPERATOR:-$HIVE_OPERATOR}"
UTAH_US_OPERATOR="${UTAH_US_OPERATOR:-$HIVE_OPERATOR}"
SINGAPORE_OPERATOR="${SINGAPORE_OPERATOR:-$HIVE_OPERATOR}"
SINGAPORE2_OPERATOR="${SINGAPORE2_OPERATOR:-$HIVE_OPERATOR}"
BERN_OPERATOR="${BERN_OPERATOR:-$HIVE_OPERATOR}"

# Failure domain — the SCHEDULING axis, and also published, so keep it opaque.
# Clients need only inequality ("these two die together / they do not"); they
# never need to learn the provider or the datacenter. Values are per-box
# pseudonyms rather than "cloudzy-utah", which would leak both.
UTAH_FAILURE_DOMAIN="${UTAH_FAILURE_DOMAIN:-fd-a1}"
UTAH_US_FAILURE_DOMAIN="${UTAH_US_FAILURE_DOMAIN:-fd-a2}"
SINGAPORE_FAILURE_DOMAIN="${SINGAPORE_FAILURE_DOMAIN:-fd-b1}"
SINGAPORE2_FAILURE_DOMAIN="${SINGAPORE2_FAILURE_DOMAIN:-fd-b2}"
BERN_FAILURE_DOMAIN="${BERN_FAILURE_DOMAIN:-fd-c1}"

deploy_server() {
    local IP=$1
    local NAME=$2
    local REGION=$3
    local MAX_MEM=$4  # systemd MemoryMax (e.g., 384M, 1G)
    local HEAP=$5     # Node --max-old-space-size in MB
    # Empty by default: unset means the relay declares no operator, which is
    # the anonymous and conservative choice (see the header). Pass an OPAQUE
    # token only if this deployment must be countable for quorum diversity.
    local OPERATOR=${6:-}
    local API_KEY_OVERRIDE=${7:-}  # optional per-relay API key override

    # Resolve effective API key (per-relay override beats env var)
    local EFFECTIVE_KEY="${API_KEY_OVERRIDE:-${API_KEY}}"
    validate_deploy_value "relay name" "$NAME" '^[A-Za-z0-9._-]{1,64}$'
    validate_deploy_value "relay IP/host" "$IP" '^[A-Za-z0-9:._-]{1,255}$'
    validate_deploy_value "relay region" "$REGION" '^[A-Za-z0-9._-]{1,32}$'
    [ -n "$OPERATOR" ] && validate_deploy_value "relay operator" "$OPERATOR" '^[A-Za-z0-9._-]{1,64}$'
    validate_deploy_value "heap size" "$HEAP" '^[0-9]{2,6}$'
    validate_deploy_value "memory limit" "$MAX_MEM" '^[0-9]+[MG]$'
    validate_api_key "$EFFECTIVE_KEY"

    local MEMORY_HIGH
    MEMORY_HIGH="$(memory_high_limit "$MAX_MEM")"

    local API_KEY_B64
    API_KEY_B64="$(printf '%s' "$EFFECTIVE_KEY" | base64 | tr -d '\n')"

    echo "═══════════════════════════════════════════════════"
    echo "  Deploying to $NAME ($IP) [region=$REGION, operator=$OPERATOR, mem=$MAX_MEM, heap=${HEAP}M]"
    echo "═══════════════════════════════════════════════════"

    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new root@"$IP" << REMOTE_SCRIPT
        set -e
        API_KEY_B64='${API_KEY_B64}'
        API_KEY_VALUE="\$(printf '%s' "\$API_KEY_B64" | base64 -d)"

        cd /root

        # ─── 1. Pull latest code ───
        if [ -d hiverelay ]; then
            cd hiverelay
            git fetch origin main
            git reset --hard origin/main
        else
            git clone https://github.com/bigdestiny2/P2P-Hiverelay.git hiverelay
            cd hiverelay
        fi

        npm install --production 2>&1 | tail -3

        # ─── 2. Kill ALL old relay processes (nohup, /opt instances, old systemd) ───
        systemctl stop hiverelay hiverelay-2 hiverelay-3 2>/dev/null || true
        systemctl disable hiverelay-2 hiverelay-3 2>/dev/null || true
        pkill -9 -f "node.*cli/index.js" 2>/dev/null || true
        pkill -9 -f "node.*/opt/hiverelay" 2>/dev/null || true
        sleep 2

        # ─── 2b. Create swap if < 1GB RAM and no swap exists ───
        TOTAL_RAM_MB=\$(free -m | awk '/Mem:/{print \$2}')
        SWAP_EXISTS=\$(swapon --show --noheadings | wc -l)
        if [ "\$TOTAL_RAM_MB" -lt 1024 ] && [ "\$SWAP_EXISTS" -eq 0 ]; then
            echo "  Low RAM (\${TOTAL_RAM_MB}MB) — creating 512MB swap..."
            fallocate -l 512M /swapfile
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
            echo "  ✓ Swap enabled"
        fi

        # ─── 2c. System prerequisite for a co-hosted index sidecar ───
        # corestore-7's storage engine (rocksdb-native, used by
        # services/index-sidecar) dynamically links libatomic.so.1, which
        # minimal Ubuntu/Debian images omit. The relay itself (corestore-6)
        # does not need it, but provision the box here so a co-located sidecar
        # starts cleanly instead of failing with a misleading require-addon
        # "Cannot find addon" crash. Idempotent — only installs when missing.
        if ! dpkg -s libatomic1 >/dev/null 2>&1; then
            echo "  Installing libatomic1 (index-sidecar prereq)..."
            apt-get update -qq && apt-get install -y libatomic1
        fi

        # ─── 3. Clear stale lock files ───
        find /root/.hiverelay -name "*.lock" -delete 2>/dev/null || true

        # ─── 4. Create systemd service ───
        install -d -m 0700 /etc/hiverelay
        umask 077
        printf 'HIVERELAY_API_KEY=%s\n' "\$API_KEY_VALUE" > /etc/hiverelay/hiverelay.env
        chmod 0600 /etc/hiverelay/hiverelay.env
        unset API_KEY_VALUE API_KEY_B64

        cat > /etc/systemd/system/hiverelay.service << 'SYSTEMD_UNIT'
[Unit]
Description=HiveRelay P2P Relay Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/hiverelay
ExecStart=/usr/bin/node --max-old-space-size=HEAP_PLACEHOLDER packages/core/cli/index.js start --mode public --region REGION_PLACEHOLDER OPERATOR_FLAG_PLACEHOLDER --auto-heal
Restart=always
RestartSec=15
KillSignal=SIGTERM
TimeoutStopSec=10
EnvironmentFile=/etc/hiverelay/hiverelay.env
Environment=NODE_ENV=production
MemoryMax=MEM_PLACEHOLDER
MemoryHigh=MEMHIGH_PLACEHOLDER
StandardOutput=append:/var/log/hiverelay.log
StandardError=append:/var/log/hiverelay.log

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/root/hiverelay /root/.hiverelay /var/log/hiverelay.log /tmp

[Install]
WantedBy=multi-user.target
SYSTEMD_UNIT

        # Replace placeholders
        sed -i "s/HEAP_PLACEHOLDER/${HEAP}/" /etc/systemd/system/hiverelay.service
        sed -i "s/REGION_PLACEHOLDER/${REGION}/" /etc/systemd/system/hiverelay.service
        # Substitute the whole flag, so an unset operator emits nothing at all
        # rather than `--operator ""` (which would publish an empty identity).
        if [ -n "${OPERATOR}" ]; then
            sed -i "s|OPERATOR_FLAG_PLACEHOLDER|--operator ${OPERATOR}|" /etc/systemd/system/hiverelay.service
        else
            sed -i "s| OPERATOR_FLAG_PLACEHOLDER||" /etc/systemd/system/hiverelay.service
        fi
        sed -i "s/MEM_PLACEHOLDER/${MAX_MEM}/" /etc/systemd/system/hiverelay.service
        sed -i "s/MEMHIGH_PLACEHOLDER/${MEMORY_HIGH}/" /etc/systemd/system/hiverelay.service

        # ─── 5. Enable and start ───
        systemctl daemon-reload
        systemctl enable hiverelay
        systemctl restart hiverelay
        sleep 3

        # ─── 6. Verify ───
        if systemctl is-active hiverelay > /dev/null 2>&1; then
            echo "  ✓ hiverelay.service is ACTIVE"
        else
            echo "  ✗ hiverelay.service FAILED — checking logs:"
            journalctl -u hiverelay --no-pager -n 10
        fi

        echo "Deployment complete on \\\$(hostname)"
REMOTE_SCRIPT

    echo "  Done: $NAME"
    echo
}

validate_deploy_value() {
    local LABEL=$1
    local VALUE=$2
    local PATTERN=$3
    if [[ ! "$VALUE" =~ $PATTERN ]]; then
        echo "Invalid $LABEL: $VALUE" >&2
        exit 1
    fi
}

validate_api_key() {
    local VALUE=$1
    if [ -z "$VALUE" ]; then
        echo "HiveRelay API key must not be empty" >&2
        exit 1
    fi
    if printf '%s' "$VALUE" | LC_ALL=C grep -q '[[:cntrl:][:space:]]'; then
        echo "HiveRelay API key must not contain whitespace or control characters" >&2
        exit 1
    fi
}

memory_high_limit() {
    local VALUE=$1
    local NUM="${VALUE%[MG]}"
    local UNIT="${VALUE: -1}"
    if [ "$UNIT" = "G" ]; then
        echo "$(( NUM * 1024 * 80 / 100 ))M"
    else
        echo "$(( NUM * 80 / 100 ))M"
    fi
}

TARGET=${1:-all}

# Push to GitHub first
echo "Pushing to GitHub..."
git push origin main 2>/dev/null || echo "Push failed — deploy from local commit"
echo

case $TARGET in
    utah)
        deploy_server "$UTAH_IP" "Utah" "NA" "384M" 256 "$UTAH_OPERATOR" "$UTAH_API_KEY"
        ;;
    utah-us)
        deploy_server "$UTAH_US_IP" "Utah-US" "NA" "1G" 512 "$UTAH_US_OPERATOR" "$UTAH_US_API_KEY"
        ;;
    singapore)
        deploy_server "$SINGAPORE_IP" "Singapore" "AS" "512M" 384 "$SINGAPORE_OPERATOR" "$SINGAPORE_API_KEY"
        ;;
    singapore-2)
        deploy_server "$SINGAPORE2_IP" "Singapore-2" "AS" "512M" 384 "$SINGAPORE2_OPERATOR" "$SINGAPORE2_API_KEY"
        ;;
    bern)
        deploy_server "$BERN_IP" "Bern" "EU" "1G" 512 "$BERN_OPERATOR" "$BERN_API_KEY"
        ;;
    all)
        deploy_server "$UTAH_IP" "Utah" "NA" "384M" 256 "$UTAH_OPERATOR" "$UTAH_API_KEY"
        deploy_server "$UTAH_US_IP" "Utah-US" "NA" "1G" 512 "$UTAH_US_OPERATOR" "$UTAH_US_API_KEY"
        deploy_server "$SINGAPORE_IP" "Singapore" "AS" "512M" 384 "$SINGAPORE_OPERATOR" "$SINGAPORE_API_KEY"
        deploy_server "$SINGAPORE2_IP" "Singapore-2" "AS" "512M" 384 "$SINGAPORE2_OPERATOR" "$SINGAPORE2_API_KEY"
        deploy_server "$BERN_IP" "Bern" "EU" "1G" 512 "$BERN_OPERATOR" "$BERN_API_KEY"
        ;;
    *)
        echo "Usage: $0 [utah|utah-us|singapore|singapore-2|bern|all]"
        exit 1
        ;;
esac

echo "═══════════════════════════════════════════════════"
echo "  All deployments complete"
echo "═══════════════════════════════════════════════════"
