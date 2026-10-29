#!/usr/bin/env bash
#
# router.sh - Turn a REMnux server into a simple NAT router
#
# Usage:
#   sudo ./router.sh status  [wan_iface]
#   sudo ./router.sh enable  <wan_iface>
#   sudo ./router.sh disable <wan_iface>
#
# <wan_iface> is the outbound (Internet-facing) interface, e.g. eth0 / ens18.

set -euo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-router.conf"

die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[*] $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") {status|enable|disable} <wan_iface>

  status  [iface]   Show IP forwarding and masquerading status
  enable  <iface>   Enable IP forwarding + NAT masquerading on <iface>
  disable <iface>   Remove masquerading on <iface> and disable IP forwarding
EOF
    exit 1
}

require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)."
}

require_iface() {
    [[ -n "${1:-}" ]] || die "Missing interface argument."
    ip link show "$1" &>/dev/null || die "Interface '$1' does not exist."
}

command -v iptables >/dev/null || die "iptables not found (apt install iptables)."

# --- IP forwarding -----------------------------------------------------------

forwarding_enabled() {
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]]
}

enable_forwarding() {
    if forwarding_enabled; then
        info "net.ipv4.ip_forward already set to 1"
    else
        info "Enabling net.ipv4.ip_forward"
        sysctl -qw net.ipv4.ip_forward=1
    fi
    # Persist across reboots
    echo "net.ipv4.ip_forward = 1" > "$SYSCTL_FILE"
}

disable_forwarding() {
    info "Disabling net.ipv4.ip_forward"
    sysctl -qw net.ipv4.ip_forward=0
    rm -f "$SYSCTL_FILE"
}

# --- Masquerading ------------------------------------------------------------

masq_rule_exists() {
    iptables -t nat -C POSTROUTING -o "$1" -j MASQUERADE 2>/dev/null
}

enable_masquerade() {
    if masq_rule_exists "$1"; then
        info "Masquerading already enabled on $1"
    else
        info "Enabling masquerading on $1"
        iptables -t nat -A POSTROUTING -o "$1" -j MASQUERADE
    fi
}

disable_masquerade() {
    if masq_rule_exists "$1"; then
        info "Removing masquerading on $1"
        # Remove all duplicates, if any
        while masq_rule_exists "$1"; do
            iptables -t nat -D POSTROUTING -o "$1" -j MASQUERADE
        done
    else
        info "No masquerading rule found on $1"
    fi
}

# --- REMnux fake services (fakedns / inetsim) --------------------------------

FAKE_SERVICES=(inetsim fakedns)

fake_service_pids() {
    # Match the process name or a script path (fakedns is often a Python script)
    pgrep -f -- "(^|/)$1( |$|\.py)" 2>/dev/null || true
}

stop_fake_services() {
    local svc pids
    for svc in "${FAKE_SERVICES[@]}"; do
        # Stop the systemd unit if there is one
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            info "Stopping systemd service $svc"
            systemctl stop "$svc"
        fi
        # Kill any remaining (manually started) instances
        pids="$(fake_service_pids "$svc")"
        if [[ -n "$pids" ]]; then
            info "Killing running $svc process(es): $(echo $pids)"
            kill $pids 2>/dev/null || true
            sleep 1
            pids="$(fake_service_pids "$svc")"
            [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null || true
        fi
    done

    # Verify nothing is left before going further
    for svc in "${FAKE_SERVICES[@]}"; do
        [[ -z "$(fake_service_pids "$svc")" ]] \
            || die "$svc is still running, refusing to enable routing."
    done
    info "fakedns / inetsim are not running"
}

show_fake_services() {
    local svc pids
    for svc in "${FAKE_SERVICES[@]}"; do
        pids="$(fake_service_pids "$svc")"
        if [[ -n "$pids" ]]; then
            echo "$svc: RUNNING (PID $(echo $pids))"
        else
            echo "$svc: not running"
        fi
    done
}

# --- Status ------------------------------------------------------------------

show_status() {
    echo "=== IP forwarding ==="
    if forwarding_enabled; then
        echo "net.ipv4.ip_forward = 1 (enabled)"
    else
        echo "net.ipv4.ip_forward = 0 (disabled)"
    fi
    [[ -f "$SYSCTL_FILE" ]] && echo "Persistent config: $SYSCTL_FILE" \
                            || echo "Persistent config: none"

    echo
    echo "=== Masquerading (nat/POSTROUTING) ==="
    if [[ -n "${1:-}" ]]; then
        if masq_rule_exists "$1"; then
            echo "$1: enabled"
        else
            echo "$1: disabled"
        fi
    else
        iptables -t nat -S POSTROUTING | grep -- '-j MASQUERADE' \
            || echo "No MASQUERADE rules found"
    fi

    echo
    echo "=== FORWARD chain policy ==="
    iptables -S FORWARD | head -n1

    echo
    echo "=== REMnux fake services ==="
    show_fake_services
}

# --- Main --------------------------------------------------------------------

[[ $# -ge 1 ]] || usage
require_root

ACTION="$1"
IFACE="${2:-}"

case "$ACTION" in
    status)
        [[ -n "$IFACE" ]] && require_iface "$IFACE"
        show_status "$IFACE"
        ;;
    enable)
        require_iface "$IFACE"
        stop_fake_services
        enable_forwarding
        enable_masquerade "$IFACE"
        echo
        show_status "$IFACE"
        ;;
    disable)
        require_iface "$IFACE"
        disable_masquerade "$IFACE"
        disable_forwarding
        echo
        show_status "$IFACE"
        ;;
    *)
        usage
        ;;
esac
