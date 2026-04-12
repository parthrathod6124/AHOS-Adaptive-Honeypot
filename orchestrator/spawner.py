"""
AHOS - Honeypot Spawner
Listens to Redis for attacker profiles from Phase 1
and auto-deploys matching Docker honeypot containers.
"""

import docker
import redis
import json
import time
from datetime import datetime

r = docker.from_env()
rd = redis.Redis(host='localhost', port=6379, decode_responses=True)

# ── Honeypot Templates per Attacker Type ──────────────
HONEYPOT_MAP = {
    "nmap_syn_scan":   "ssh",
    "masscan":         "ssh",
    "linux_manual":    "http",
    "windows_manual":  "http",
    "shodan_crawler":  "http",
    "unknown_scanner": "ftp",
}

CONTAINER_CONFIGS = {
    "ssh": {
        "image":   "cowrie/cowrie:latest",
        "ports":   {"2222/tcp": 2222},
        "name":    "ahos-honeypot-ssh",
    },
    "http": {
        "image":   "nginx:alpine",
        "ports":   {"80/tcp": 8080},
        "name":    "ahos-honeypot-http",
    },
    "ftp": {
        "image":   "fauria/vsftpd",
        "ports":   {"21/tcp": 2121},
        "name":    "ahos-honeypot-ftp",
    },
}

# ── Active container tracker ───────────────────────────
active_containers = {}


def spawn_honeypot(tool: str, src_ip: str):
    """Spawn a honeypot container based on attacker tool."""
    honeypot_type = HONEYPOT_MAP.get(tool, "ftp")
    config        = CONTAINER_CONFIGS[honeypot_type]

    container_name = f"{config['name']}-{src_ip.replace('.', '_')}"

    # Don't spawn duplicate for same IP
    if container_name in active_containers:
        print(f"[SPAWNER] Container already running for {src_ip}")
        return

    print(f"[SPAWNER] {src_ip} → Detected as '{tool}'")
    print(f"[SPAWNER] Deploying {honeypot_type.upper()} honeypot...")

    try:
        container = r.containers.run(
            image    = config["image"],
            ports    = config["ports"],
            name     = container_name,
            detach   = True,
            remove   = True,
        )
        active_containers[container_name] = {
            "container": container,
            "src_ip":    src_ip,
            "tool":      tool,
            "type":      honeypot_type,
            "spawned":   datetime.utcnow().isoformat()
        }
        print(f"[SPAWNER] ✅ {honeypot_type.upper()} honeypot live for {src_ip}")
        print(f"[SPAWNER] Container ID: {container.short_id}\n")

    except docker.errors.APIError as e:
        print(f"[SPAWNER] ❌ Failed to spawn: {e}\n")


def kill_old_containers(max_age_seconds=300):
    """Kill honeypot containers older than max_age_seconds."""
    now = datetime.utcnow()
    to_remove = []

    for name, info in active_containers.items():
        spawned = datetime.fromisoformat(info["spawned"])
        age     = (now - spawned).total_seconds()
        if age > max_age_seconds:
            try:
                info["container"].kill()
                print(f"[SPAWNER] Killed expired container: {name}")
                to_remove.append(name)
            except Exception:
                to_remove.append(name)

    for name in to_remove:
        del active_containers[name]


def list_active():
    """Print all active honeypot containers."""
    if not active_containers:
        print("[SPAWNER] No active honeypots")
        return
    print("\n[SPAWNER] Active Honeypots:")
    for name, info in active_containers.items():
        print(f"  → {info['type'].upper()} | IP: {info['src_ip']} | Tool: {info['tool']}")


class HoneypotSpawner:

    def start(self):
        """Subscribe to Redis and spawn honeypots on attacker detection."""
        pubsub = rd.pubsub()
        pubsub.subscribe("attacker_detected")

        print("[SPAWNER] Listening for attacker profiles from Phase 1...\n")

        for message in pubsub.listen():
            if message["type"] != "message":
                continue

            try:
                profile = json.loads(message["data"])
                tool    = profile.get("detected_tool", "unknown_scanner")
                src_ip  = profile.get("src_ip", "0.0.0.0")
                threat  = profile.get("threat_level", "low")

                print(f"[SPAWNER] Profile received → {src_ip} | {tool} | {threat}")
                spawn_honeypot(tool, src_ip)
                kill_old_containers()

            except json.JSONDecodeError:
                continue