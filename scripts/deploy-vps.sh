#!/bin/bash
# Deploy HiveRelay to VPS servers
# Usage: HIVERELAY_RELEASE_TARGET=vX.Y.Z ./scripts/deploy-vps.sh <active-relay>
#
# Creates a systemd service with auto-restart, memory limits, and proper region tagging.
# Kills any old processes from /opt/hiverelay or nohup before enabling the systemd service.

set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/hiverelay_fleet}"
KNOWN_HOSTS="${HIVERELAY_FLEET_KNOWN_HOSTS:?Set HIVERELAY_FLEET_KNOWN_HOSTS to an absolute pinned known_hosts file}"
API_KEY="${HIVERELAY_API_KEY:?Set HIVERELAY_API_KEY environment variable}"
RELEASE_TARGET="${HIVERELAY_RELEASE_TARGET:?Set HIVERELAY_RELEASE_TARGET to an exact signed release tag}"

if [[ ! "$RELEASE_TARGET" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "HIVERELAY_RELEASE_TARGET must be an exact release tag" >&2
    exit 1
fi

case "$KNOWN_HOSTS" in
    /*) ;;
    *) echo "HIVERELAY_FLEET_KNOWN_HOSTS must be an absolute path" >&2; exit 1 ;;
esac
if [ ! -r "$KNOWN_HOSTS" ] || [ ! -f "$KNOWN_HOSTS" ] || [ -L "$KNOWN_HOSTS" ]; then
    echo "Pinned known_hosts file is missing, unreadable, or unsafe: $KNOWN_HOSTS" >&2
    exit 1
fi

# Server IPs
UTAH_US_IP="${UTAH_US_IP:-144.172.91.26}"
UTAH_2GB_A_IP="${UTAH_2GB_A_IP:-216.126.237.3}"
UTAH_8GB_IP="${UTAH_8GB_IP:-144.172.97.68}"
SINGAPORE_IP="${SINGAPORE_IP:-104.194.153.179}"
SINGAPORE2_IP="${SINGAPORE2_IP:-104.194.152.121}"
DUBAI_IP="${DUBAI_IP:-172.86.76.209}"

# Per-relay API keys (override the env-var fallback so each relay gets its own
# strong key). Set via env var to rotate without editing this script.
UTAH_US_API_KEY="${UTAH_US_API_KEY:-}"
UTAH_2GB_A_API_KEY="${UTAH_2GB_A_API_KEY:-}"
UTAH_8GB_API_KEY="${UTAH_8GB_API_KEY:-}"
SINGAPORE_API_KEY="${SINGAPORE_API_KEY:-}"
SINGAPORE2_API_KEY="${SINGAPORE2_API_KEY:-}"
DUBAI_API_KEY="${DUBAI_API_KEY:-}"

# Per-relay operator identifiers (for AutoHeal v2 sybil resistance).
# Singapore-1 and Singapore-2 share a region but get distinct operator IDs
# so the diversity-enforced replica scheduler treats them as separate nodes.
UTAH_US_OPERATOR="${UTAH_US_OPERATOR:-hive-foundation-utah-us}"
UTAH_2GB_A_OPERATOR="${UTAH_2GB_A_OPERATOR:-hive-foundation-utah-2gb-a}"
UTAH_8GB_OPERATOR="${UTAH_8GB_OPERATOR:-hive-foundation-utah-8gb}"
SINGAPORE_OPERATOR="${SINGAPORE_OPERATOR:-hive-foundation-singapore}"
SINGAPORE2_OPERATOR="${SINGAPORE2_OPERATOR:-hive-foundation-singapore-2}"
DUBAI_OPERATOR="${DUBAI_OPERATOR:-hive-foundation-dubai}"

deploy_server() {
    local IP=$1
    local NAME=$2
    local REGION=$3
    local MAX_MEM=$4  # systemd MemoryMax (e.g., 384M, 1G)
    local HEAP=$5     # Node --max-old-space-size in MB
    local OPERATOR=${6:-hive-foundation}  # operator identifier for AutoHeal v2 sybil resistance
    local API_KEY_OVERRIDE=${7:-}  # optional per-relay API key override

    # Resolve effective API key (per-relay override beats env var)
    local EFFECTIVE_KEY="${API_KEY_OVERRIDE:-${API_KEY}}"
    validate_deploy_value "relay name" "$NAME" '^[A-Za-z0-9._-]{1,64}$'
    validate_deploy_value "relay IP/host" "$IP" '^[A-Za-z0-9:._-]{1,255}$'
    validate_deploy_value "relay region" "$REGION" '^[A-Za-z0-9._-]{1,32}$'
    validate_deploy_value "relay operator" "$OPERATOR" '^[A-Za-z0-9._-]{1,64}$'
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

    ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o UpdateHostKeys=no -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o GlobalKnownHostsFile=/dev/null root@"$IP" << REMOTE_SCRIPT
		set -euo pipefail
		API_KEY_B64='${API_KEY_B64}'
		API_KEY_VALUE="\$(printf '%s' "\$API_KEY_B64" | base64 -d)"

		# Fail before pull/install/service mutation when the relay cannot run this
		# release line. The repository engines floor is Node.js 20.
		NODE_VERSION="\$(/usr/bin/node --version 2>/dev/null)" || {
			echo "Node.js >=20 is required before deployment" >&2
			exit 1
		}
		case "\$NODE_VERSION" in
			v[0-9]*.[0-9]*.[0-9]*) ;;
			*) echo "Unrecognized Node.js version: \$NODE_VERSION" >&2; exit 1 ;;
		esac
		NODE_MAJOR="\${NODE_VERSION#v}"
		NODE_MAJOR="\${NODE_MAJOR%%.*}"
		if [ "\$NODE_MAJOR" -lt 20 ]; then
			echo "Node.js >=20 is required before deployment; found \$NODE_VERSION" >&2
			exit 1
		fi

		cd /root

        # ─── 1. Resolve an exact signed release ───
        if [ -d hiverelay ]; then
            cd hiverelay
        else
            git clone https://github.com/bigdestiny2/P2P-Hiverelay.git hiverelay
            cd hiverelay
        fi
        if [ ! -f /etc/hiverelay/allowed-signers ] || [ -L /etc/hiverelay/allowed-signers ]; then
            echo "Trusted /etc/hiverelay/allowed-signers is required" >&2
            exit 1
        fi
        git fetch --force origin "refs/tags/${RELEASE_TARGET}:refs/tags/${RELEASE_TARGET}"
        git -c core.hooksPath=/dev/null \
            -c core.fsmonitor=false \
            -c gpg.format=ssh \
            -c gpg.ssh.allowedSignersFile=/etc/hiverelay/allowed-signers \
            -c gpg.ssh.program=/usr/bin/ssh-keygen \
            verify-tag --raw "${RELEASE_TARGET}"
        git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
            checkout --detach --force "${RELEASE_TARGET}^{commit}"
        [ -z "\$(git status --porcelain=v1 --untracked-files=all)" ] || {
            echo "Exact signed release checkout is not clean" >&2
            exit 1
        }
        [ "\$(/usr/bin/node -p \"require('./package.json').version\")" = "${RELEASE_TARGET#v}" ] || {
            echo "Signed tag/package version mismatch" >&2
            exit 1
        }

        npm ci --omit=dev --no-audit --no-fund \
            --include-workspace-root \
            --workspace packages/core \
            --workspace packages/services \
            --workspace packages/client \
            --workspace packages/verifier 2>&1 | tail -3

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
ExecStart=/usr/bin/node --max-old-space-size=HEAP_PLACEHOLDER packages/core/cli/index.js start --mode public --region REGION_PLACEHOLDER --operator OPERATOR_PLACEHOLDER --auto-heal
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
        sed -i "s/OPERATOR_PLACEHOLDER/${OPERATOR}/" /etc/systemd/system/hiverelay.service
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
            exit 1
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

TARGET=${1:?Usage: HIVERELAY_RELEASE_TARGET=vX.Y.Z $0 [utah-2gb-a|utah-us|utah-8gb|sing-1|sing-2|dubai]}

case $TARGET in
    utah-2gb-a)
        deploy_server "$UTAH_2GB_A_IP" "utah-2gb-a" "NA" "1G" 512 "$UTAH_2GB_A_OPERATOR" "$UTAH_2GB_A_API_KEY"
        ;;
    utah-us)
        deploy_server "$UTAH_US_IP" "utah-us" "NA" "1G" 512 "$UTAH_US_OPERATOR" "$UTAH_US_API_KEY"
        ;;
    utah-8gb)
        deploy_server "$UTAH_8GB_IP" "utah-8gb" "NA" "6G" 4096 "$UTAH_8GB_OPERATOR" "$UTAH_8GB_API_KEY"
        ;;
    sing-1)
        deploy_server "$SINGAPORE_IP" "sing-1" "APAC" "512M" 384 "$SINGAPORE_OPERATOR" "$SINGAPORE_API_KEY"
        ;;
    sing-2)
        deploy_server "$SINGAPORE2_IP" "sing-2" "APAC" "512M" 384 "$SINGAPORE2_OPERATOR" "$SINGAPORE2_API_KEY"
        ;;
    dubai)
        deploy_server "$DUBAI_IP" "dubai" "ME" "1G" 768 "$DUBAI_OPERATOR" "$DUBAI_API_KEY"
        ;;
    *)
        echo "Usage: HIVERELAY_RELEASE_TARGET=vX.Y.Z $0 [utah-2gb-a|utah-us|utah-8gb|sing-1|sing-2|dubai]"
        exit 1
        ;;
esac

echo "═══════════════════════════════════════════════════"
echo "  All deployments complete"
echo "═══════════════════════════════════════════════════"
