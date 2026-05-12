# Deploying a new scan worker

Distributed workers run **`worker-api`** (FastAPI). They **register** and **lease** chunks from the coordinator HTTP API, then run **`pd-asn-pipeline`** scan containers on the same host via **`docker run`** and the mounted **`docker.sock`**.

---

## 1. Prerequisites (before you start)

| Requirement | Notes |
|-------------|--------|
| **OS** | Linux with **Docker Engine** + **Docker Compose v2**. |
| **Repo layout on the worker machine** | Build context for the worker image is **`asn-edge/`** (parent of `worker/`). You need **`asn-edge/shared/`**, **`asn-edge/worker/`**, and **`asn-edge/worker/Dockerfile`**. Clone or copy the **`asn-edge`** tree—not only the `worker/` folder. |
| **Scanner image** | Image tag from `worker/config/worker.yml` → **`scanner.image`** (default **`pd-asn-pipeline:latest`**). Build: `cd asn-edge/scanner && docker compose build`, or `docker load` an image tarball from another host. |
| **Coordinator reachable from the worker** | From **inside** `worker-api`, `http://{coordinator_api_host}:{coordinator_api_port}` must reach the coordinator API (e.g. **`127.0.0.1:7000`** only works if that address is correct **inside the worker container**—often use **`network_mode: host`** on `worker-api`, or **`host.docker.internal`** / bridge gateway + `extra_hosts`; SSH **`-R`** tunnels are common—see **`coordinator/open_tunnels.sh`**. |
| **Coordinator can reach the worker control API** (optional but recommended) | For **`GET /health`** probes, cancel, and ops: coordinator must reach **`http://{control_bind_host}:{control_bind_port}/health`** as exposed from the worker (often **`0.0.0.0:8001`** on the worker + SSH **`-L`** on the coordinator host—see **`coordinator/open_tunnels.sh`**). |

---

## 2. Configure the worker (`worker.yml` + `.env`)

1. Copy **`config/worker.yml`** and set:
   - **`worker.worker_id`**: globally unique string (e.g. `submarine`, `black`).
   - **`worker.coordinator_api_host` / `worker.coordinator_api_port`**: must work **from inside `worker-api`** after deploy.
   - **`worker.control_bind_host` / `worker.control_bind_port`**: where the worker listens (default **`0.0.0.0:8001`**).
   - **`worker.work_root` / `worker.log_root`**: must match how volumes are mounted in **`docker-compose.yml`** (defaults **`/var/lib/scanner/work`**, **`/var/log/scanner`**).
2. Create **`worker/.env`** from **`.env.example`**:
   - **`WORKER_ID`**: must match **`worker.worker_id`** (Compose passes this; it **overrides** yaml in `app/settings.py`).

---

## 3. Chunk bind mounts (`Missing config file: /work/config.json`)

`worker-api` runs **`docker run -v <chunk_dir>:/work ...`**. The path **`<chunk_dir>`** must be one the **Docker daemon on the host** resolves to the **same directory** where chunk files were written (usually **`{work_root}/{chunk_id}`** inside `worker-api`).

**If `worker-api` runs in a container** with only **`docker.sock`** and a **named volume** for `work_root`, the daemon often resolves **`/var/lib/scanner/work/...` on the host**, which is **not** the same as inside the container → **empty `/work`** in the scanner → entrypoint fails.

**Diagnostic** (from **`asn-edge/worker/`**, use a **`chunk_id` directory that exists on this host** under `work_root`):

```bash
docker compose exec worker-api sh -c '
  d=/var/lib/scanner/work/naabu_scan_YOURSCAN_YOURHASH
  echo "=== worker-api ==="
  ls -la "$d/config.json" || true
  echo "=== same -v as worker (daemon view) ==="
  docker run --rm -v "$d:/work" alpine ls -la /work/config.json
'
```

- **First line OK, second fails** → fix bind source (recommended: bind-mount a **real host directory** to `work_root` in **`docker-compose.yml`**, e.g. `- /srv/scanner/work:/var/lib/scanner/work`, create **`/srv/scanner/work`** on the host, keep **`work_root`** as **`/var/lib/scanner/work`** in yaml).
- **Both OK** → bind chain is good for that host.

**`network_mode: host`** on `worker-api`: Compose may warn that **`ports:`** are ignored; you can remove **`ports:`** or ignore the warning.

---

## 4. Build and run (`worker-api`)

```bash
cd asn-edge/worker
docker compose build
docker compose up -d
# after config/image changes:
docker compose up -d --force-recreate
```

---

## 5. Coordinator: register the worker in config and tunnels

**Lease / register API** does **not** read `coordinator.yml`; workers self-register. You still configure the coordinator so **workers reach `:7000`** and **optional `/health` lists each worker** as reachable.

### 5.1 `coordinator/config/coordinator.yml` — `workers:`

Add a **new list entry** under **`workers:`** (see existing entries):

| Field | Purpose |
|-------|--------|
| **`worker_id`** | Same string as this machine’s **`WORKER_ID` / `worker.worker_id`**. |
| **`worker_control_host`** | Hostname/IP **`coordinator-api`** uses for **`GET http://{host}:{port}/health`** (must work **from inside the coordinator container**). With tunnels on the Docker host, **`host.docker.internal`** + a **local forwarded port** is typical. |
| **`worker_control_port`** | Port matching that probe (e.g. **`9101`** if **`open_tunnels.sh`** maps **`9101` → worker `127.0.0.1:8001`**). |

**Note:** Nested **`capacity:`** under each worker in the sample yaml is **not** loaded by the current **`WorkerRoute`** model (extra keys ignored); safe to omit or keep for human documentation only.

### 5.2 `coordinator/docker-compose.yml`

Ensure **`coordinator-api`** can resolve **`worker_control_host`** (e.g. **`extra_hosts: host.docker.internal:host-gateway`** when probing ports bound on the Docker host).

### 5.3 SSH tunnels (`coordinator/open_tunnels.sh`)

For an automated flow (patch `tunnel_common.sh` and `coordinator.yml`, recycle `coordinator-api`, install Docker on the VPS from `asn-worker.zip`, build scanner/worker, then `./open_tunnels.sh`), see **`coordinator/new_worker.sh`** and `coordinator/AGENTS.md`.

On the **coordinator host** (machine running Docker for the stack):

1. Edit **`WORKERS`** (SSH `Host` aliases) and **`LOCAL_WORKER_PORTS`** (one unique port per worker); arrays must stay the same length.
2. Run the script. It opens **`-L 0.0.0.0:<local_port>:127.0.0.1:8001`** to each worker’s control API and **`-R`** so workers can reach coordinator **`:7000`** on their side.

Align **`LOCAL_WORKER_PORTS`** with **`worker_control_port`** in **`coordinator.yml`**.

### 5.4 Restart coordinator

After changing **`coordinator.yml`**:

```bash
cd coordinator
docker compose up -d --force-recreate coordinator-api
```

---

## 6. Smoke checks

| Check | Command / expectation |
|-------|----------------------|
| Worker → coordinator | From worker: `curl -fsS http://<coordinator_host>:7000/health` |
| Coordinator → worker control | Same URL as **`worker_control_host:port`** in **`coordinator.yml`** (e.g. tunnel port): `curl -fsS http://host.docker.internal:9101/health` |
| Coordinator aggregate health | `curl -fsS http://127.0.0.1:7000/health` — each configured worker should show **`reachable: true`** when tunnels and binds are correct |
| Worker logs | `docker compose logs -f worker-api` — lease / execute / scanner errors |

---

## 7. Reference paths in this repo

| Topic | Path |
|-------|------|
| Worker compose | `asn-edge/worker/docker-compose.yml` |
| Worker app config | `asn-edge/worker/config/worker.yml` |
| Worker env example | `asn-edge/worker/.env.example` |
| Scanner image build | `asn-edge/scanner/docker-compose.yml` |
| Coordinator compose | `coordinator/docker-compose.yml` |
| Coordinator app config | `coordinator/config/coordinator.yml` |
| Tunnel helper | `coordinator/open_tunnels.sh` |
| Automated new worker (coordinator host) | `coordinator/new_worker.sh` |
