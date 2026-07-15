# Connect HexaCore to a Kali VirtualBox VM (the no-Docker path)

You do **not** need Docker. If you'd rather run the security tools inside a normal Kali Linux
virtual machine, HexaCore can talk to it over SSH. Set it up once, type the VM's IP into the
console (or `.env`), click **Test connection**, and you're ready.

There are two ways. **Option A (Vagrant)** is almost zero clicks. **Option B (ISO)** is the
"I want to install Kali from the ISO myself" path you asked for — a few clicks, no command-line
skills required.

---

## Option A — Vagrant (recommended, ~zero clicks)

1. Install [VirtualBox](https://www.virtualbox.org/) and [Vagrant](https://www.vagrantup.com/).
2. In a terminal: `cd infra/vm && vagrant up`
   Vagrant downloads a ready-made Kali box, boots it, installs the tools, and enables SSH. No
   installer questions.
3. The VM comes up at **192.168.56.20**. In the HexaCore console → **Settings → Tool runner**,
   choose **VM**, host `192.168.56.20`, user `vagrant`, and paste the key Vagrant printed (or use
   `vagrant ssh-config` to see it). Click **Test connection** → green.

That's it. See `Vagrantfile` in this folder.

---

## Option B — Install Kali from the ISO yourself (VirtualBox)

For when you specifically want to attach an ISO and install Kali by hand. This is the simple,
click-through path.

### 1. Make the VM
1. Install **VirtualBox**.
2. Download the **Kali Linux Installer ISO** from kali.org.
3. VirtualBox → **New** → Name "kali", Type Linux, Version Debian 64-bit → 4096 MB RAM, 40 GB
   disk → Create.
4. Select the VM → **Settings → Storage** → click the empty disc → choose your `kali.iso` → OK.

### 2. Set the network so HexaCore can reach it (the "IP / subnet" part)
This is the one important setting. It gives the VM a fixed address on a private network shared
with your PC.

1. VM → **Settings → Network → Adapter 2** → **Enable**, "Attached to: **Host-only Adapter**"
   (name usually `vboxnet0`). Leave Adapter 1 as NAT (that gives the VM internet). → OK.
2. Boot the VM and install Kali (accept the defaults; set a username/password you'll remember).
3. After it boots, open a terminal in Kali and turn on SSH:
   ```
   sudo systemctl enable --now ssh
   ip addr                     # find the host-only address, e.g. 192.168.56.20
   ```
   If you want to **set the IP yourself** (your "change the IP / subnet mask" idea):
   ```
   sudo ip addr add 192.168.56.20/24 dev eth1      # 255.255.255.0 = /24
   ```
   (The host-only network is `192.168.56.0/24` by default in VirtualBox.)

### 3. Tell HexaCore
- **In the console:** Settings → Tool runner → **VM** → host `192.168.56.20`, user = the Kali
  username you set, and either an SSH key (recommended) or your password → **Test connection**.
- **Or on the command line:**
  ```
  make runner-check                              # uses .env
  # or, quick one-off:
  PYTHONPATH=tools python -m hexacore_tools.backends.cli --vm-host 192.168.56.20 --vm-user kali
  ```
  A green `[OK] connected to kali@192.168.56.20:22` means HexaCore can drive the VM.

### 4. Install the tools in the VM (one time)
Inside Kali:
```
sudo apt update && sudo apt install -y nmap nuclei subfinder httpx-toolkit ffuf nikto \
  whatweb testssl.sh dnsutils jq
```

---

## SSH key (recommended over a password)

On your PC:
```
ssh-keygen -t ed25519 -f ~/.ssh/hexacore_kali -N ""
ssh-copy-id -i ~/.ssh/hexacore_kali.pub kali@192.168.56.20
```
Then point HexaCore at `~/.ssh/hexacore_kali`. No password prompts, and `make runner-check`
works non-interactively.

---

## Switching between Docker and the VM

It's one setting. `.env`:
```
HEXACORE_RUNNER_BACKEND=vm      # or docker, local, dryrun
HEXACORE_VM_HOST=192.168.56.20
```
Nothing else in the platform changes — the same capabilities, scope validation, and approval
gates apply no matter where the tool actually runs.
