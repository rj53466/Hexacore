# infra/ — deployment, tool-runner, and the pluggable execution backend

HexaCore is **not tied to Docker**. A capability's command line is built once by its adapter;
*where* it runs is a single setting (`HEXACORE_RUNNER_BACKEND`, or the console's Tool-runner page):

| Backend | Where tools run | Setup |
|---|---|---|
| `dryrun` | nowhere (builds the command only) | none — default / CI |
| `local` | this host | tools installed locally |
| `docker` | ephemeral Kali container per run | `make kali-build` (see `kali/Dockerfile`) |
| `vm` | a Kali VirtualBox/appliance over SSH | `vm/README.md` — point it at the VM's IP |

The backend implementations live in [`tools/hexacore_tools/backends/`](../tools/hexacore_tools/backends/);
switching them changes nothing else in the platform — the same scope validation and approval
gates apply regardless of where a tool executes.

## Files

- `docker-compose.yml` — platform datastores (postgres, redis, minio). `make up` / `make down`.
- `kali/Dockerfile` — the Kali tool-runner image for the `docker` backend. `make kali-build`.
- `runner.example.json` — copy to `runner.json`; the shape the console's settings page saves.
- `vm/README.md` — layman guide to attach a Kali VirtualBox VM (Vagrant or ISO) by IP.
- `vm/Vagrantfile` — zero-touch prebuilt Kali VM for the `vm` backend.

## Quick start (Docker path)

```bash
cp .env.example .env         # set HEXACORE_RUNNER_BACKEND=docker
make up                      # postgres + redis + minio
make kali-build              # build hexacore/kali-tools
make runner-check            # -> [OK] docker server <version>
```

## Quick start (VM path, no Docker)

```bash
# in .env: HEXACORE_RUNNER_BACKEND=vm ; HEXACORE_VM_HOST=192.168.56.20
make runner-check            # -> [OK] connected to kali@192.168.56.20:22
```

See `vm/README.md` for the full walkthrough.

## Still pending

Postgres persistence for the API (SQLAlchemy/Alembic, Epic A3), api/agent/console container
images, and per-target egress firewalling for tool containers (Epic C19).
