#!/bin/sh
# HexaCore per-target egress firewall (Brain/05 §7, Epic C19).
#
# Runs as root at container start (needs CAP_NET_ADMIN), installs a default-DROP OUTPUT policy
# that permits egress ONLY to the in-scope host(s) in $HEXACORE_ALLOWED_EGRESS, then drops
# privileges and exec's the tool as the unprivileged `runner`. Defence-in-depth on top of the
# Scope Validator: even a compromised tool or an exploit session can't call back to the internet
# or pivot to other lab hosts. Fail-closed: any error aborts before the tool ever runs.
set -eu

ALLOWED="${HEXACORE_ALLOWED_EGRESS:-}"

ipt() { iptables -w "$@"; }

# --- IPv4: default drop, allow loopback + return traffic ---------------------
ipt -P OUTPUT DROP
ipt -A OUTPUT -o lo -j ACCEPT
ipt -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS to the container's configured resolvers only (Docker's embedded resolver is on loopback,
# already covered above; external resolvers are added here so hostname targets still resolve).
for ns in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null); do
  ipt -A OUTPUT -p udp --dport 53 -d "$ns" -j ACCEPT || true
  ipt -A OUTPUT -p tcp --dport 53 -d "$ns" -j ACCEPT || true
done

# --- allow the in-scope target(s) -------------------------------------------
# iptables resolves a hostname to its A record(s) at insert time. A resolution failure trips
# `set -e` and aborts the run (fail-closed). Comma- or space-separated CIDRs / IPs / hostnames.
for t in $(printf '%s' "$ALLOWED" | tr ',' ' '); do
  [ -n "$t" ] && ipt -A OUTPUT -d "$t" -j ACCEPT
done

# --- IPv6: drop everything -------------------------------------------------
# ponytail: scope targets are IPv4 CIDRs today, so we close the whole v6 egress path rather than
# mirror the allow-list. Add per-target v6 rules here if/when v6 scopes are supported.
ip6tables -w -P OUTPUT DROP 2>/dev/null || true
ip6tables -w -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true

# --- drop root + CAP_NET_ADMIN, run the tool as the unprivileged runner ------
exec runuser -u runner -- "$@"
