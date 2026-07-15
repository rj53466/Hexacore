# HexaCore Kali tool-runner (Brain/07 §4, Brain/08 §5).
# Ephemeral container: the platform runs one per tool invocation (`docker run --rm`), egress
# firewalled to in-scope targets, then tears it down. Installs ONLY the Phase-1 tools the
# platform drives — small, auditable, fast to rebuild. ZAP / Burp DAST / Metasploit RPC run as
# their own services, not in this image.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      # recon (passive)
      subfinder amass dnsutils whatweb \
      # scan (active)
      nmap masscan nuclei nikto ffuf gobuster \
      # tls
      testssl.sh sslscan \
      # http probing
      httpx-toolkit \
      # supporting
      ca-certificates curl jq git \
      # egress firewall (entrypoint) — util-linux provides runuser for the privilege drop
      iptables util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash runner
WORKDIR /home/runner

# The entrypoint applies a default-drop egress firewall (allow only $HEXACORE_ALLOWED_EGRESS),
# then drops root and runs the tool as `runner`. Starts as root; the container is launched with
# --cap-drop ALL --cap-add NET_ADMIN (set the firewall) --cap-add SETUID --cap-add SETGID (drop
# to the unprivileged user). The tool process itself ends up with none of these capabilities.
COPY hexacore-egress.sh /usr/local/bin/hexacore-egress
RUN chmod +x /usr/local/bin/hexacore-egress
ENTRYPOINT ["/usr/local/bin/hexacore-egress"]
# `docker run --rm hexacore/kali-tools <tool> <args>` -> firewall -> runs one command as runner.
